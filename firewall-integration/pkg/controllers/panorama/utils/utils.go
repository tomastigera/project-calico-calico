// Copyright 2019-2025 Tigera Inc. All rights reserved.
package utils

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	panw "github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/objs/addr"
	"github.com/PaloAltoNetworks/pango/objs/addrgrp"
	"github.com/PaloAltoNetworks/pango/objs/srvc"
	"github.com/PaloAltoNetworks/pango/pnrm/dg"
	"github.com/PaloAltoNetworks/pango/poli/security"
	log "github.com/sirupsen/logrus"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	pkgutil "github.com/projectcalico/calico/firewall-integration/pkg/util"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// Panorama address types.
	IpNetmask  = "ip-netmask"
	IpRange    = "ip-range"
	Fqdn       = "fqdn"
	IpWildcard = "ip-wildcard" // Panorama 9.0+

	// Non RFC1123 compliant characters
	nonRFCCompliantRegexDef            = `[^a-z0-9\.\-]+`
	nameRFC1123LabelFmt                = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
	nameRFC1123SubdomainFmt            = nameRFC1123LabelFmt + "(\\." + nameRFC1123LabelFmt + ")*"
	nameContainsHashLikeSuffixRegexDef = `[-][a-z0-9]{5}$`

	// Matching period and hyphen regex defs constants
	charactersConvertedToPeriodRegex      = `[.-]*[.][.-]*`
	charactersMatchingPrefixOrSuffixRegex = `^[.-]*|[.-]*$`

	// Hash constants.
	hashShortenedPrefix        = "-"
	numHashChars               = 5
	lenOfMaxRfc1123WithoutHash = k8svalidation.DNS1123LabelMaxLength - (len(hashShortenedPrefix) + numHashChars)

	tagsDelimiterDelimitersRegexDef = `(?m)[^\s\,"']+|"([^"]*)"|'([^']*)'`

	// Dynamic match filter conversion constants.
	matchDelimitersRegexDef = `(?m)[^\s\)\("']+|"([^"]*)"|'([^']*)'`
)

type AddressGroupsFilter set.Set[string]

type PanoramaClient interface {
	Get(url string, response *pkgutil.PredefinedSecurityRulesResponse) ([]byte, error)
	GetAddressEntries(dg string) ([]addr.Entry, error)
	GetAddressGroupEntries(dg string) ([]addrgrp.Entry, error)
	GetAddressGroups(dg string) ([]string, error)
	GetClient() *panw.Panorama
	GetDeviceGroupEntry(dg string) (dg.Entry, error)
	GetDeviceGroups() ([]string, error)
	GetPostRulePolicies(dg string) ([]security.Entry, error)
	GetPreRulePolicies(dg string) ([]security.Entry, error)
	GetServiceEntries(dg string) ([]srvc.Entry, error)
}

type PanoramaApiClient struct {
	client *panw.Panorama
}

type AddressGroup struct {
	Entry addrgrp.Entry
	// The matching addresses to this address group.
	// Functionality maintains the address slices in sorted order.
	Addresses Addresses
	// An error encountered while processing.
	Err error
}

type Addresses struct {
	// IpNetmasks type addresses.
	IpNetmasks []string
	// Fqdn type addresses.
	Fqdns []string
	// IpRange type addresses.
	IpRanges []string
	// IpWildcard type addresses.
	IpWildcards []string
}

func NewPANWClient(cfg *config.Config) (*PanoramaApiClient, error) {
	p := &PanoramaApiClient{
		client: &panw.Panorama{Client: panw.Client{
			Hostname: cfg.FwHostName,
			Username: cfg.FwUserName,
			Password: cfg.FwPassword,
			Timeout:  cfg.FwTimeout,
			Logging:  uint32(panw.LogAction),
		}},
	}

	log.Debugf("Initialize client with hostname: %s", p.GetClient().Hostname)
	if err := p.GetClient().Initialize(); err != nil {
		return p, err
	}

	log.Infof("Client created for host name: %s", p.GetClient().Hostname)
	return p, nil
}

func NewTSEEClient(pConfig *config.Config) (datastore.ClientSet, error) {
	// create client-set.
	clientSet := datastore.MustGetClientSet()
	if clientSet == nil {
		return nil, fmt.Errorf("error setting-up datastore client interface")
	}

	return clientSet, nil
}

// Get returns a list of predefined security rules entries. Returns an error if
// pango:Get returns an error.
func (p *PanoramaApiClient) Get(url string, response *pkgutil.PredefinedSecurityRulesResponse) ([]byte, error) {
	return p.client.Get(url, nil, response)
}

// GetAddressEntries returns a list of the device group's address entries. Returns an error if
// pango:Objects.Address.GetAll returns an error.
func (p *PanoramaApiClient) GetAddressEntries(dg string) ([]addr.Entry, error) {
	return p.client.Objects.Address.GetAll(dg)
}

// GetAddressGroupEntries returns a list of the device group's address group entries. Returns an
// error if pango:Objects.AddressGroup.GetAll returns an error.
func (p *PanoramaApiClient) GetAddressGroupEntries(dg string) ([]addrgrp.Entry, error) {
	return p.client.Objects.AddressGroup.GetAll(dg)
}

// GetAddressGroups returns a list of the device group's address group names. Returns an error
// if pango:Objects.AddressGroup.GetList returns an error.
func (p *PanoramaApiClient) GetAddressGroups(dg string) ([]string, error) {
	return p.client.Objects.AddressGroup.GetList(dg)
}

// GetClient returns the pango client.
func (p *PanoramaApiClient) GetClient() *panw.Panorama {
	return p.client
}

// GetDeviceGroupEntry returns a device group entry. Returns an error if
// pango:Panorama.DeviceGroup.Show returns an error.
func (p *PanoramaApiClient) GetDeviceGroupEntry(dg string) (dg.Entry, error) {
	return p.client.Panorama.DeviceGroup.Show(dg)
}

// GetDeviceGroups returns the device group names. Returns an error if
// pango:Panorama.DeviceGroup.GetList returns an error.
func (p *PanoramaApiClient) GetDeviceGroups() ([]string, error) {
	return p.client.Panorama.DeviceGroup.GetList()
}

// GetPostRulePolicies returns the device group's post-rule policies. Returns an error if
// pango:Policies.Security.GetAll returns an error.
func (p *PanoramaApiClient) GetPostRulePolicies(dg string) ([]security.Entry, error) {
	return p.client.Policies.Security.GetAll(dg, "post-rulebase")
}

// GetPreRulePolicies returns the device group's pre-rule policies. Returns an error if
// pango:Policies.Security.GetAll returns an error.
func (p *PanoramaApiClient) GetPreRulePolicies(dg string) ([]security.Entry, error) {
	return p.client.Policies.Security.GetAll(dg, "pre-rulebase")
}

// GetServiceEntries returns the device group's service entries. Returns an error if
// pango:Objects.Services.GetAll returns an error.
func (p *PanoramaApiClient) GetServiceEntries(dg string) ([]srvc.Entry, error) {
	return p.client.Objects.Services.GetAll(dg)
}

// AddressGroups returns the list of address groups that match the filter parameter. Returns an
// error if the Panorama client is unavailable.
// The filter is a set of tags of type string and their names have been converted to the k8s naming
// scheme (RFC1123).
func GetAddressGroups(client PanoramaClient, filter AddressGroupsFilter, dg string) ([]AddressGroup, error) {
	var err error

	if client.GetClient() == nil {
		err = errors.New("panorama client unavailable")
		return nil, err
	}

	log.Info("Accessing Panorama resource")
	addressGroups := []AddressGroup{}
	addressGroupEntries, err := client.GetAddressGroupEntries(dg)
	if err != nil {
		log.Debugf("failed to retrieve address group list, %s\n", err.Error())
		return addressGroups, err
	}
	addresses, err := client.GetAddressEntries(dg)
	if err != nil {
		log.Debugf("failed to retrieve addresses list, %s\n", err.Error())
		return addressGroups, err
	}

	// Add address groups that map to tags filter.
	for _, entry := range addressGroupEntries {
		for _, tag := range entry.Tags {
			if filter.Contains(tag) {
				// Set an empty list of IP type buckets, per address group.
				buckets := &Addresses{
					IpNetmasks:  []string{},
					Fqdns:       []string{},
					IpRanges:    []string{},
					IpWildcards: []string{},
				}
				// An address group is defined as either static in which case a list of associated
				// addresses is mapped via static list, or is defined to be dynamic, in which case
				// each mapped address is defined by its dynamic match.
				if len(entry.DynamicMatch) != 0 {
					// Dynamic address group.
					err = setAddressBucketsByDynamicMatch(buckets, entry.DynamicMatch, addresses)
				} else if len(entry.StaticAddresses) != 0 {
					// Static address group.
					setAddressBucketsByStaticAddresses(buckets, entry.StaticAddresses, addresses)
				} else {
					// A valid address group in Panorama can be either static or dynamic.
					log.Debugf("Dynamic match and static addresses of address group: \"%s\", cannot both be empty", entry.Name)
					err = fmt.Errorf("address group: \"%s\", contains an empty dynamic match and an empty static list of addresses", entry.Name)
				}
				addressGroup := AddressGroup{
					Entry:     entry,
					Addresses: *buckets,
					Err:       err,
				}
				addressGroups = append(addressGroups, addressGroup)
				// A tag match occurred with this address group, no reason add an address group more than
				// once.
				break
			}
		}
	}

	return addressGroups, nil
}

// QueryDeviceGroup queries the provided device group name. If the query returns an error,
// then the function passes the error to the caller.
func QueryDeviceGroup(client PanoramaClient, dg string) error {
	// Querying the "shared" device group returns an error.
	if dg == "shared" {
		return nil
	}

	dglist, err := client.GetDeviceGroups()
	if err == nil {
		deviceGroupsSet := set.FromArray(dglist)
		if !deviceGroupsSet.Contains(dg) {
			log.Errorf("device group: \"%s\", does not exist.", dg)

			return fmt.Errorf("device group: \"%s\" does not exist", dg)
		}

		return nil
	}

	return err
}

// setAddressBucketsByDynamicMatch maps each available address to the sorted list of IP type
// buckets, by matching against a dynamic match filter. The contents of addresses are in sorted by
// address name (string) order. An error is returned if either the match is empty, the match
// conversion to selector parser fails, or the selector parsing fails.
func setAddressBucketsByDynamicMatch(buckets *Addresses, match string, addresses []addr.Entry) error {
	// Return and empty result if the list of unordered static addresses is empty.
	if len(match) == 0 {
		return fmt.Errorf("failed to retrieve the address values buckets from an empty dynamic match")
	}

	// Convert the dynamic match to a selector.
	sel, err := ConvertMatchFilterToSelector(match)
	if err != nil {
		return err
	}
	log.Debugf("match: \"%s\" converted to selector: \"%s\"", match, sel)
	// Parse the selector expression.
	parsedSel, err := selector.Parse(sel)
	if err != nil {
		log.WithError(err).Debugf("failed parsing selector: %s", sel)
		return err
	}

	// Iterate through the list of addresses, only adding addresses to the result with matching tags.
	for _, address := range addresses {
		labels := make(map[string]string)
		for _, tag := range address.Tags {
			// Convert to a valid selector format.
			labels[GetRFC1123Name(tag)] = ""
		}
		if parsedSel.Evaluate(labels) {
			// Place each address into its appropriate bucket, ipNetmask, fqdn, ipRange, or ipWildcard.
			insertAddressIntoBucket(buckets, address.Type, address.Value)
		}
	}
	sortAddressBuckets(buckets)

	return nil
}

// setAddressBucketsByStaticAddresses maps each available address to the sorted list of IP type
// buckets, by matching against a static list of address names. The contents of each address bucket
// is sorted by address name (string) order. The static addresses will be an empty (not nil) result
// if the static address entry is empty.
func setAddressBucketsByStaticAddresses(buckets *Addresses, staticAddresses []string, addresses []addr.Entry) {
	// Return and empty result if the list of unordered static addresses is empty.
	if len(staticAddresses) == 0 {
		return
	}
	// Add the static address names into a set.
	addressNameMap := make(map[string]bool)
	for _, addressName := range staticAddresses {
		addressNameMap[addressName] = true
	}
	// Iterate through the list of addresses, only adding addresses which match the set of static
	// addresses.
	for _, address := range addresses {
		if addressNameMap[address.Name] {
			// Place each address into its appropriate bucket, ipNetmask, fqdn, ipRange, or ipWildcard.
			insertAddressIntoBucket(buckets, address.Type, address.Value)
		}
	}
	sortAddressBuckets(buckets)
}

// ConvertMatchFilterToSelector returns a selector string that has been converted from a dynamic
// match filter.
// An address group's DynamicMatch is a logical operation on Panorama tags. convertToSelector
// operates on top of the Panorama DynamicMatch validation rules. Statements are separated by
// operators AND/OR and grouped by parentheses. Names of tags may or may not be encapsulated
// by single quotes. Single quotes are used to encapsulate names that may contain delimiters.
//
// Algorithm:
//  1. Split the match string by delimeters [\(, \), \', \", \s], preserving single and double
//     quotes.
//     Preserve single and double quotes to differentiate cases where tag names may
//     be either 'or' or "AND" that are not logical operators. Delimiters that lie
//     within single or double quotes are not interpreted as such, and remain as
//     part of the words, ie. 'my() tag' will be interpreted as a word. The begining and end of a
//     sentence is the empty delimiter, i.e it will occupy an index in the delimiters array.
//     Consecutive delimiters are placed into the same index.
//  2. Combine the delimiters and modified words into an array representing the selector equivalent.
//     Encapsulate words with "has()", convert AND/and to "&&", and OR/or to "||",
//     and remove single and double quotes. By definition the delimiters will always have greater
//     length than the number of words.
//     Base case, match: "" defines words: [] (empty), delimiters: [""].
//     Simple cases,
//     match: "tag1" defines words[tag1], delimiters: ["", ""].
//     match: "\stag1" defines words[tag1], delimiters: ["\s", ""]. Note: \s defines a space.
//     match: "(tag1)" defines words[tag1], delimiters: ["(", ")"].
//     match: "'tag1'" defines words['tag1'], delimiters: ["", ""].
//     match: "\"tag1\"" defines words[\"tag1\"], delimiters: ["", ""].
//  3. Join the words from step (2.) and delimiters from step (3.) into a single selector string.
//
// Example input:
//
//	match filter: "('tag1' or ('tag2'     OR tag3 and tag4)) and 'tag5'"
//
// Step 1 - Get words and delimiters from the match string:
//
//	words : ['tag1', or, 'tag2', OR, tag3, and, tag4, and, 'tag5']
//	delimeters: ["", " ", " (", "     ", " ", " ", " ", ")) ", " ", ""] : len(10)
//
// Step 2 - Insert the delimiters and modified (selector format) words into a selector Array in order:
// ["", has(tag1), " ", ||, " (", has(tag2), "     ", ||, " ", has(tag3), " ", &&, " ", has(tag4), ")) ", &&, " ", has(tag5), ""]
// Output - Join the selector array into a single string:
//
//	"(has(tag1) || (has(tag2)     || has(tag3) && has(tag4))) && has(tag5)"
func ConvertMatchFilterToSelector(match string) (string, error) {
	// Split the match filter into its components words and delimiters.
	words, delimiters := getMatchFilterWordsAndDelimiters(match)
	if len(words) >= len(delimiters) {
		return "", errors.New("cannot create selector for this set of words and delimiters")
	}
	// Operate on each word and place the match components back into the selectorArray.
	selectorArray := []string{}
	j := 0
	for i := 0; i < len(words) && j < len(delimiters); i, j = i+1, j+1 {
		selectorArray = append(selectorArray, delimiters[j])
		switch {
		case words[i] == "and" || words[i] == "AND":
			selectorArray = append(selectorArray, "&&")
			continue
		case words[i] == "or" || words[i] == "OR":
			selectorArray = append(selectorArray, "||")
			continue
		case strings.HasPrefix(words[i], "'") && strings.HasSuffix(words[i], "'"):
			words[i] = strings.TrimPrefix(words[i], "'")
			words[i] = strings.TrimSuffix(words[i], "'")
		case strings.HasPrefix(words[i], "\"") && strings.HasSuffix(words[i], "\""):
			words[i] = strings.TrimPrefix(words[i], "\"")
			words[i] = strings.TrimSuffix(words[i], "\"")
		}
		// Convert words with non-RFC1123 characters and encapsulate the word within the selector prefix
		// and suffix "has(...)"
		words[i] = "has(" + GetRFC1123Name(words[i]) + ")"
		selectorArray = append(selectorArray, words[i])
	}

	// By definition, the number delimiters in a match filter will always be greater than the number
	// of the words in a match filter.
	for ; j < len(delimiters); j++ {
		selectorArray = append(selectorArray, delimiters[j])
	}
	// Finally, join the selector array to get the selector string.
	selector := strings.Join(selectorArray, "")

	return selector, nil
}

// getMatchFilterWordsAndDelimiters splits a dynamic match filter into an array of its words and an
// array of its delimiters. The delimiters are defined by matchDelimitersDefinition. The delimiters
// are [\(, \), \', \", \s]. Words that have been delimited by "'" or "\"" will be an empty
// delimiter. Consecutive delimiters are placed within the same delimiter array index. The begining
// and end of the match string are an empty string delimiter.
//
// Example input:
//
//	match filter: "word0 or((word1 and    \"word  )2\")or word3 and'word4')and'word5'"
//
// output:
//
//	words: "[word0, or, word1, \"word  )2\", or, word3, and, 'word4', and, 'word5']"
//	delimiters: "["", " ", "((", " ", "    ", ")", " ", " ", "", ")", "", ""]"
func getMatchFilterWordsAndDelimiters(match string) (words, delimiters []string) {
	regex := regexp.MustCompile(matchDelimitersRegexDef)
	// Find all strings that do not match the delimiters.
	words = regex.FindAllString(match, -1)
	// Split the string into its delimiters.
	delimiters = regex.Split(match, -1)

	return words, delimiters
}

// insertAddressIntoBucket maps the address value into its bucket. The buckets represent the
// possible IP types an address value can have; ipNetmask, fqdn, ipRange, or ipWildcard.
func insertAddressIntoBucket(addresses *Addresses, addressType, addressValue string) {
	switch addressType {
	case IpNetmask:
		addresses.IpNetmasks = append(addresses.IpNetmasks, addressValue)
	case Fqdn:
		addresses.Fqdns = append(addresses.Fqdns, addressValue)
	case IpRange:
		addresses.IpRanges = append(addresses.IpRanges, addressValue)
	case IpWildcard:
		addresses.IpWildcards = append(addresses.IpWildcards, addressValue)
	default:
		log.Debugf("%s is an unsupported address type", addressValue)
	}
}

// sortAddressBuckets sorts each address type bucket.
func sortAddressBuckets(addresses *Addresses) {
	sort.Strings(addresses.IpNetmasks)
	sort.Strings(addresses.Fqdns)
	sort.Strings(addresses.IpRanges)
	sort.Strings(addresses.IpWildcards)
}

// GetRFC1123Name converts and returns a name to an RFC 1123 compliant name. Returns an empty string
// if the name is empty.
// The name must:
// - start with an alphabetic character
// - end with an alphanumeric character
// - contain at most 63 characters
// - contain only lowercase alphanumeric characters or '-' or '.'
func GetRFC1123Name(name string) string {
	// Used to avoid name clashing with a generated hash suffix.
	hasHashLikeSuffix := regexp.MustCompile(nameContainsHashLikeSuffixRegexDef).MatchString
	// If the name is already in a valid RFC1123 Label format and does not contain a hash like suffix,
	// just return the original name.
	if len(name) <= k8svalidation.DNS1123LabelMaxLength && !hasHashLikeSuffix(name) &&
		isValidRFC1123Name(name) {

		return name
	}

	// The name is not in RFC1123 label format, at least one conversion has to occur to make it valid.
	// An empty string will contain a wildcard 'z' character, along with a hash suffix.

	rfcNonAlphaCharPeriod := "."
	rfcWildcard := "z"

	// Convert all uppercase to lower case, in order to preserve as many characters as possible.
	// Remove each non-RFC compliant character.
	rfcName := strings.ToLower(name)

	// Remove all characters that are not RFC1123.
	regexInvalidChars := regexp.MustCompile(nonRFCCompliantRegexDef)
	rfcName = regexInvalidChars.ReplaceAllString(rfcName, "")
	// Replace '-.', '.-' or consecutive '.' with a single '.'.
	regexPeriods := regexp.MustCompile(charactersConvertedToPeriodRegex)
	rfcName = regexPeriods.ReplaceAllString(rfcName, rfcNonAlphaCharPeriod)
	// Remove all '.' or '-' from the prefix and suffix of the name.
	regexPrefixSuffix := regexp.MustCompile(charactersMatchingPrefixOrSuffixRegex)
	rfcName = regexPrefixSuffix.ReplaceAllString(rfcName, "")

	// If all characters have been removed, replace the empty string with a 'z'.
	if len(rfcName) == 0 {
		rfcName = rfcWildcard
	}

	// Get hash from the original name, to preserve the uniqueness in mapping.

	// If the length of the name with the hash appended exceeds the length of DNS1123LabelMaxLength,
	// then cut the length of the rfcName, so that its length with the hash is less than the length of
	// DNS1123LabelMaxLength.
	if len(rfcName) > lenOfMaxRfc1123WithoutHash {
		if rfcName[lenOfMaxRfc1123WithoutHash-1] == '.' {
			// If the last character of the substring of rfcName is '.', remove it, to avoid introducing
			// an invalid string of the form ".-" into the name.
			rfcName = rfcName[:lenOfMaxRfc1123WithoutHash-1]
		} else {
			rfcName = rfcName[:lenOfMaxRfc1123WithoutHash]
		}
	}

	return rfcName + hashShortenedPrefix + hash(name, numHashChars)
}

// GetRFC1123PolicyName returns a policy name that is RFC 1123 compliant. It assumes that the tier
// name is RFC 1123 compliant, and does not contains the '.' character, and with length that is less
// than half lenOfMaxRfc1123WithoutHash. Returns an empty string if the name is empty.
// The resulting name must:
// - start with an alphabetic character
// - end with an alphanumeric character
// - contain at most 63 characters
// - contain only lowercase alphanumeric characters or '-'
func GetRFC1123PolicyName(tier, name string) (string, error) {
	if len(tier) >= lenOfMaxRfc1123WithoutHash/2 || !pkgutil.IsValidTierName(tier) {
		return "", fmt.Errorf("invalid tier name: '%s'", tier)
	}

	// Used to avoid name clashing with a generated hash suffix.
	hasHashLikeSuffix := regexp.MustCompile("[-][a-z0-9]{5}$").MatchString
	// If the name prefixed with the tier is already in a valid RFC1123 Label format and does not
	// contain a hash like suffix, just return the original name.
	nameWithTierPrefix := fmt.Sprintf("%s.%s", tier, name)
	if len(nameWithTierPrefix) <= k8svalidation.DNS1123LabelMaxLength &&
		!hasHashLikeSuffix(nameWithTierPrefix) && isValidRFC1123PolicyName(name) {

		return nameWithTierPrefix, nil
	}

	// The name is not in RFC1123 label format, at least one conversion has to occur to make it valid.
	// An empty string will contain a wildcard 'z' character, along with a hash suffix.

	rfcWildcard := "z"

	// Convert all uppercase to lower case, in order to preserve as many characters as possible.
	// Remove each non-RFC compliant character.
	rfcName := strings.ToLower(name)

	// Remove all characters that are not RFC1123, and the '.' character.
	regexInvalidChars := regexp.MustCompile(`[^a-z0-9\\-]+`)
	rfcName = regexInvalidChars.ReplaceAllString(rfcName, "-")
	// Remove all '-' from the prefix and suffix of the name.
	regexPrefixSuffix := regexp.MustCompile("^[.-]*|[.-]*$")
	rfcName = regexPrefixSuffix.ReplaceAllString(rfcName, "")

	// If all characters have been removed, replace the empty string with a 'z'.
	if len(rfcName) == 0 {
		rfcName = rfcWildcard
	}

	// Concatenate the tier with the policy RFC1123 valid name.
	rfcName = fmt.Sprintf("%s.%s", tier, rfcName)

	// Get hash from the original name, to preserve the uniqueness in mapping.

	// If the length of the name with the hash appended exceeds the length of DNS1123LabelMaxLength,
	// then cut the length of the rfcName, so that its length with the hash is less than the length of
	// DNS1123LabelMaxLength.
	if len(rfcName) > lenOfMaxRfc1123WithoutHash {
		if rfcName[lenOfMaxRfc1123WithoutHash-1] == '-' {
			// If the last character of the substring of rfcName is '-', remove it.
			rfcName = rfcName[:lenOfMaxRfc1123WithoutHash-1]
		} else {
			rfcName = rfcName[:lenOfMaxRfc1123WithoutHash]
		}
	}

	return rfcName + hashShortenedPrefix + hash(name, numHashChars), nil
}

// hash returns a hash string generated from the input value and equal in length to the number of
// characters passed in as input, or the length of the resulting hash value, if its length is less
// than the number of chars. The hasher is sha256, with a base32 encoding, with 'Z' padding.
// The encoded value is defined as a string of lower case characters.
func hash(value string, numOfChars int) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(value))
	enc := base32.HexEncoding.WithPadding('Z')
	hash := strings.ToLower(enc.EncodeToString(hasher.Sum(nil)))
	// Return the substring equal in length to the numOfChars, as long as numOfChars is less than the
	// length of the resulting hash calculated in the previous step. Otherwise, return the entire
	// length of the hash.
	if numOfChars < len(hash) {
		return hash[:numOfChars]
	} else {
		return hash
	}
}

// SplitTags splits the string of tags onto an array and returns the result. The function parses
// over a comma delimeted list of tags. The tags are in order, following the example of the API.
// It is assumed that non-RFC1123 tag names are contained within single quotes. An error is returned
// when the parsing fails, either when an odd number of single quotes is encountered, or a tag name
// with non-RFC1123 character set is not encapsulated within single quotes.
func SplitTags(tags string) ([]string, error) {
	tagsArray := []string{}
	// Split the input by one or more space and comma characters. Trim the single quotes.
	var delimeter = regexp.MustCompile(tagsDelimiterDelimitersRegexDef)
	for _, tag := range delimeter.FindAllString(tags, -1) {
		// Each prefix (single quote) should have a matching suffix, otherwise return an error.
		// Return an error if a tag name with non-RFC1123 character set is not encapsulated within
		// single quotes.
		if strings.HasPrefix(tag, "'") {
			trimmedPrefix := strings.TrimPrefix(tag, "'")
			trimmedSuffix := strings.TrimSuffix(trimmedPrefix, "'")
			if trimmedSuffix == trimmedPrefix {
				return []string{},
					errors.New("failed to parse tags. Odd number of single quotes identified")
			}
			tag = trimmedSuffix
		} else if strings.HasSuffix(tag, "'") {
			return []string{},
				errors.New("failed to parse tags. Odd number of single quotes identified")
		} else if !isValidRFC1123Name(tag) {
			return []string{}, errors.New("failed to parse tags. Names containing non RFC1123 chars " +
				"must be encapsulated within single quotes")
		}
		tagsArray = append(tagsArray, tag)
	}
	sort.Strings(tagsArray)
	log.Debugf("tags: %s was split into: %s", tags, tagsArray)

	return tagsArray, nil
}

// isValidRFC1123Name return true if the name is a valid RFC1123 name.
// The name must:
// - start with an alphabetic character
// - end with an alphanumeric character
// - contain only lowercase alphanumeric characters or '-' or '.'
// - does not contain ".-" or "-." substrings.
// Note: This will not validate the character length is a maximum of 63 characters.
func isValidRFC1123Name(name string) bool {
	// Names must follow a simple subdomain DNS1123 format.
	isValidLabelNameFmt := regexp.MustCompile("^" + nameRFC1123SubdomainFmt + "$").MatchString

	return isValidLabelNameFmt(name)
}

// isValidRFC1123PolicyName return true if the name is a valid RFC1123 policy name.
// The name must:
// - start with an alphabetic character
// - end with an alphanumeric character
// - contain only lowercase alphanumeric characters or '-'
// - does not contain ".-" or "-." substrings.
// Note: This will not validate the character length is a maximum of 63 characters.
func isValidRFC1123PolicyName(name string) bool {
	nameRFC1123PolicyLabelFmt := "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
	nameRFC1123PolicySubdomainFmt := nameRFC1123PolicyLabelFmt + "(" + nameRFC1123PolicyLabelFmt + ")*"
	// Names must follow a simple subdomain DNS1123 format.
	isValidLabelNameFmt := regexp.MustCompile("^" + nameRFC1123PolicySubdomainFmt + "$").MatchString

	return isValidLabelNameFmt(name)
}
