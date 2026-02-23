// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package bgp

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// Timeout for querying BIRD
	birdTimeOut = 2 * time.Second
	// BIRD binary for IPv6 has a suffix
	birdSuffixIPv6 = "6"
	// Delimiter used for IPv4 addresses
	delimiterIPv4 = "."
	// Delimiter used for IPv6 addresses
	delimiterIPv6 = ":"
)

var (
	// When checking BIRD status output the following are valid prefixes for each row of output.
	// "0001" code means BIRD is ready.
	// "1000" code shows the BIRD version
	// "1011" shows uptime
	// Row starting with a " " is another row of data
	validPrefixesRegex = regexp.MustCompile(`^(?:0001|1000|1011|[\s]+){1}(.+)$`)

	regex struct {
		versionHeader *regexp.Regexp
		protocol      struct {
			tableHeader   *regexp.Regexp
			summary       *regexp.Regexp
			routes        *regexp.Regexp
			importUpdates *regexp.Regexp
			ignoreRow     *regexp.Regexp
		}
	}

	// Mapping the BIRD type extracted from the peer name to the display type.
	bgpTypeMap = map[string]string{
		"Global": "global",
		"Mesh":   "node-to-node mesh",
		"Node":   "node specific",
	}
)

func init() {
	regex.versionHeader = regexp.MustCompile(`^(?:0001)?\s+BIRD\s+v.+ready.*$`)

	regex.protocol.tableHeader = regexp.MustCompile(`^(?:2002\-)?\s*name\s+proto\s+table\s+state\s+since\s+info(.*)$`)
	regex.protocol.summary = regexp.MustCompile(`^(?:1002\-)(Global|Node|Mesh)_(.+)$`)
	regex.protocol.routes = regexp.MustCompile(`^\s+Routes:\s+(.*)$`)
	regex.protocol.importUpdates = regexp.MustCompile(`^\s+(?:Import)\s(?:updates):\s+(\d+|---)\s+(\d+|---)\s+(\d+|---)\s+(\d+|---)\s+(\d+|---)\s*$`)

	// We use ignoreRow regex as a catch all case, to match valid rows of output
	// that we do not care about capturing or validating against.
	// For example, the below rows are all examples of lines we should ignore
	// (but still match):
	//    Route change stats:     received   rejected   filtered    ignored   accepted
	//         Neighbor graceful restart active
	//         Export updates:             52         16         32        ---          4
	regex.protocol.ignoreRow = regexp.MustCompile(`^(?:1006\-)?\s+[^:]+[:]?\s+.+\s*$`)
}

// ParseError represents an error when parsing BIRD output. Using a custom error type
// makes test validation easier.
type ParseError struct {
	msg   string
	value string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: %s", e.msg, e.value)
}

// GetPeers returns pointer to created Stats object containing a slice of Peers
// extracted from BIRD or BIRD6 (depending on the given IP version specified by
// the input param ipVer).
func GetPeers(ipVer Version) (*Stats, error) {
	log.Debugf("Retrieve BIRD peers for %s", ipVer)
	// Attempt to get a connection to BIRD socket
	c, err := getConnection(ipVer)
	if err != nil {
		return nil, err
	}
	defer c.Close() // nolint: errcheck

	// To query the current state of the BGP peers, we connect to the BIRD
	// socket and send a "show protocols all" message.  BIRD responds with
	// peer data in a table format.
	_, err = c.Write([]byte("show protocols all\n"))
	if err != nil {
		return nil, fmt.Errorf("Error executing command: unable to write to BIRD socket: %s", err)
	}

	// Scan the output and collect parsed BGP peers
	log.Debugln("Reading output from BIRD")
	peers, err := parsePeers(ipVer, c)
	if err != nil {
		return nil, fmt.Errorf("Error executing command: %v", err)
	}

	return &Stats{
		Type:  Peers,
		IPVer: ipVer,
		Data:  peers,
	}, nil
}

// IsInGracefulRestart determines whether the BIRD daemon is currently in grace
// restart (GR) mode. It returns true if GR mode is occurring. Otherwise, it returns
// false.
func IsInGracefulRestart(ipVer Version) (bool, error) {
	// Attempt to get a connection to BIRD socket
	c, err := getConnection(ipVer)
	if err != nil {
		return false, err
	}
	defer c.Close() // nolint: errcheck

	// To query the current status of the BGP daemon, we connect to the BIRD socket
	// and send a "show status" message. BIRD responds with its status in a table format.
	_, err = c.Write([]byte("show status\n"))
	if err != nil {
		return false, fmt.Errorf("Error executing command: unable to write to BIRD socket: %s", err)
	}

	scanner := bufio.NewScanner(c)

	// Set a time-out for reading from the socket connection.
	if err := c.SetReadDeadline(time.Now().Add(birdTimeOut)); err != nil {
		return false, err
	}

	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		text := scanner.Text()
		log.Debugf("Read: %s\n", text)

		if hasGR, stop, err := containsGracefulRestart(text); err != nil {
			return false, err
		} else if hasGR {
			return true, nil
		} else if stop {
			break
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		if err := c.SetReadDeadline(time.Now().Add(birdTimeOut)); err != nil {
			return false, err
		}
	}

	return false, scanner.Err()
}

// getConnection attempts to create a connection through the BIRD socket.
func getConnection(ipVer Version) (net.Conn, error) {
	// Figure out which version of BIRD based on IP version
	birdSuffix := ""
	if ipVer == IPv6 {
		birdSuffix = birdSuffixIPv6
	}

	// Try connecting to the BIRD socket in `/var/run/calico/` first to get the data
	c, err := net.Dial("unix", fmt.Sprintf("/var/run/calico/bird%s.ctl", birdSuffix))
	if err != nil {
		// If that fails, try connecting to BIRD socket in `/var/run/bird` (which is the
		// default socket location for BIRD install) for non-containerized installs
		log.Debugln("Failed to connect to BIRD socket in /var/run/calico, trying /var/run/bird")
		c, err = net.Dial("unix", fmt.Sprintf("/var/run/bird/bird%s.ctl", birdSuffix))
		if err != nil {
			return nil, fmt.Errorf("Error querying BIRD: unable to connect to BIRDv%s socket: %v", ipVer, err)
		}
	}
	return c, nil
}

// parsePeers scans through BIRD output to return a slice of Peers.
// See test function TestPeer_parsePeer for sample output from BIRD.
func parsePeers(ipVer Version, conn net.Conn) ([]Peer, error) {
	// Determine the separator to use for an IP address, based on the
	// IP version.
	ipSeparator := delimiterIPv4
	if ipVer == IPv6 {
		ipSeparator = delimiterIPv6
	}

	scanner := bufio.NewScanner(conn)

	// Set a time-out for reading from the socket connection.
	if e := conn.SetReadDeadline(time.Now().Add(birdTimeOut)); e != nil {
		return nil, e
	}

	// Validate that the beginning rows of output are what we expect using
	// the defined validators. Order of the validators in the slice matters.
	// e.g.
	//      0001 BIRD v0.3.3+birdv1.6.8 ready.
	//      2002-name     proto    table    state  since       info
	validators := []regexp.Regexp{
		*regex.versionHeader,
		*regex.protocol.tableHeader,
	}
	if err := validateRows(scanner, validators); err != nil {
		return nil, err
	}

	var peers []Peer
	// Now proceed to consume the remaining output in multi-line chunks (one
	// check per peer)
	peerOutput := ""
	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		line := scanner.Text()
		log.Debugf("Read: %s\n", line)

		// We expect a single empty line in the output between peers (or end)
		if isEmptyString(line) || strings.HasPrefix(line, "0000") {
			// Given a non-empty output for a peer, we are ready to parse it
			if !isEmptyString(peerOutput) {
				if peer := parsePeerDetails(peerOutput, ipSeparator); peer != nil {
					peers = append(peers, *peer)
				}

				// Reset output buffer (ready to collate lines for next peer)
				peerOutput = ""
			}
		} else {
			// Otherwise, continue to collate lines of output for the current peer
			peerOutput += (line + "\n")
		}

		// "0000" means end of data
		if strings.HasPrefix(line, "0000") {
			break
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		if e := conn.SetReadDeadline(time.Now().Add(birdTimeOut)); e != nil {
			return nil, e
		}
	}

	return peers, scanner.Err()
}

// Parse the given line of output from BIRD command show protocols all.  Returns a
// Peer struct if successful, nil otherwise.
// See test function TestPeer_parsePeer for sample output from BIRD.
func parsePeerSummary(line, ipSeparator string, peer *Peer) bool {
	// Split into fields.  We expect at least 6 columns:
	// 	name, proto, table, state, since and info.
	// The info column contains the BGP state plus possibly some additional
	// info (which will be columns > 6).
	//
	// Peer names will be of the format described by regex.protocol.summary.
	columns := strings.Fields(line)
	if len(columns) < 6 {
		return false
	}
	if columns[1] != "BGP" {
		return false
	}

	// Check the name of the peer is of the correct format.  This regex
	// returns two components:
	// -  A type (Global|Node|Mesh) which we can map to a display type
	// -  An IP address (with _ separating the octets)
	sm := regex.protocol.summary.FindStringSubmatch(columns[0])
	if len(sm) != 3 {
		return false
	}
	var ok bool
	peer.PeerIP = strings.ReplaceAll(sm[2], "_", ipSeparator)
	if peer.PeerType, ok = bgpTypeMap[sm[1]]; !ok {
		return false
	}

	// Store remaining columns (piecing back together the info string)
	peer.State = columns[3]
	peer.Since = columns[4]
	peer.BGPState = columns[5]
	if len(columns) > 6 {
		peer.Info = strings.Join(columns[6:], " ")
	}

	return true
}

// parsePeerDetails attempts to parse all details for a BGP peer from the given
// text output. For each line of output, attempt to apply each of the parsers
// in sequence, with the expectation that each line should pass exactly one of
// the parsers. If all lines pass parsing, then return a Peer struct with filled
// in values.
// Otherwise, there was something in the output that did not match with what was
// expected for details for a BGP peer. In that case, return nil.
func parsePeerDetails(output, ipSeparator string) *Peer {
	r := strings.NewReader(output)
	scanner := bufio.NewScanner(r)

	// Store various sections of the peer details output.
	peer := &Peer{}

	// Set up a series of parsers each one designed to parse a different part of
	// the peer details output.
	// NOTE: Order here matters. We want the ignoreRow parser to always be last.
	parsers := []func(string) bool{
		func(s string) bool { return parsePeerSummary(s, ipSeparator, peer) },
		func(s string) bool { return parseRoutes(s, &peer.Details.RouteCounts) },
		func(s string) bool { return parseImportUpdates(s, &peer.Details.ImportUpdateCounts) },
		func(s string) bool { return ignoreRow(s) },
	}

	for scanner.Scan() {
		line := scanner.Text()
		if !applyParsers(line, parsers) {
			return nil
		}
	}

	return peer
}

// ignoreRow is a dummy catch-all parser. We simply want to validate the output
// matches a generic structure, i.e. roughly '<key>: <value>'.
// This is because there are sections in the peer details output that we are not
// concerned with storing. If we decide in the future to store them, we will add
// new parsers to capture them.
func ignoreRow(line string) bool {
	return regex.protocol.ignoreRow.MatchString(line)
}

// parseRoutes attempts to validate and capture the 'Routes' row within the peer
// details.
//
// This row looks something like this ('filtered' may or may not be present):
//
//	Routes:         1 imported, 1 filtered, 1 exported, 1 preferred
func parseRoutes(line string, prc *PeerRouteCounts) bool {
	groups := regex.protocol.routes.FindStringSubmatch(line)
	if groups == nil {
		return false
	}

	routePairs := strings.SplitSeq(groups[1], ",")
	for p := range routePairs {
		trimmed := strings.TrimSpace(p)
		values := strings.Split(trimmed, " ")
		switch values[1] {
		case "imported":
			prc.NumImported = parseInt(values[0])
		case "exported":
			prc.NumExported = parseInt(values[0])
		case "filtered":
			prc.NumFiltered = parseInt(values[0])
		case "preferred":
			prc.NumPreferred = parseInt(values[0])
		default:
			// Shouldn't happen, unexpected route type
			return false
		}
	}

	return true
}

// parseImportUpdates attempts to validate and capture the 'Import updates' row
// within the peer details section called 'Route change stats'.
//
// This row looks like this:
//
//	Route change stats:     received   rejected   filtered    ignored   accepted
//	  Import updates:              2          0          0          1          1
func parseImportUpdates(line string, iuc *PeerImportUpdateCounts) bool {
	groups := regex.protocol.importUpdates.FindStringSubmatch(line)
	if groups == nil {
		return false
	}

	iuc.NumReceived = parseInt(groups[1])
	iuc.NumRejected = parseInt(groups[2])
	iuc.NumFiltered = parseInt(groups[3])
	iuc.NumIgnored = parseInt(groups[4])
	iuc.NumAccepted = parseInt(groups[5])

	return true
}

// Convenience function to iterate over a list of parsers and attempt to
// apply each to a given line of text. Halt as soon as one of the parsers
// passes (returns true). Used within parsePeerDetails function.
func applyParsers(line string, parsers []func(s string) bool) bool {
	for _, parser := range parsers {
		if parser(line) {
			log.Debugf("Parsing line: '%s' ... passed", line)
			return true
		}
	}
	// If all parsers ran but none passed, then we consider the entire process
	// to have failed (there was something unexpected about this particular
	// line of text)
	log.Debugf("Parsing line: '%s' ... failed", line)
	return false
}

// validateRows iterates through a series of validators (regexs) in sequential order and
// attempts to match each against a single line of text from the given scanner.
// The order of the validators matters.
// Each validator regex is applied to a single line of output from the scanner. If a line
// could not be scanned or does not match the corresponding validator, an error is returned.
// Otherwise, when all validators have matched, nil is returned.
func validateRows(scanner *bufio.Scanner, validators []regexp.Regexp) error {
	// Attempt to read the next line of output from scanner and match
	// against the current regex validator
	for _, v := range validators {
		if ok := scanner.Scan(); !ok {
			return &ParseError{"unexpected output line from BIRD", scanner.Err().Error()}
		}
		if !v.MatchString(scanner.Text()) {
			return &ParseError{"unexpected output line from BIRD", scanner.Err().Error()}
		}
	}
	return nil
}

// containsGracefulRestart determines whether a GR has happened or not. If GR has
// not occurred, then determine whether to continue or stop. If a line does not
// have one of the recognized prefixes then return an error.
func containsGracefulRestart(line string) (hasGR, stop bool, err error) {
	// "0024" code indicates the start of a graceful restart status report.
	// This means a GR is in progress.
	if strings.HasPrefix(line, "0024") {
		return true, false, nil
	} else if strings.HasPrefix(line, "0013") {
		// Stop on "0013" code, which means final line.
		return false, true, nil
	} else if validPrefixesRegex.MatchString(line) {
		// See comment for validPrefixesRegex for valid prefix codes.
		return false, false, nil
	}
	// Format of row is unexpected.
	return false, false, &ParseError{"unexpected output line from BIRD", line}
}

// isEmptyString determines whether the given string s is empty (ignoring whitespace).
// Returns true if s (after trimming) is empty, false otherwise.
func isEmptyString(s string) bool {
	return len(strings.TrimSpace(s)) == 0
}

// parseInt converts a given string into uint32 (since that is the data type BIRD
// uses). A parse int error should never happen (given we trust BIRD's values
// to be uint32).
func parseInt(s string) uint32 {
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return uint32(0)
	}
	return uint32(i)
}
