// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package review

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/lma/pkg/timeutils"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

// UnusedPolicies implements the "calicoctl review unused-policies" command.
func UnusedPolicies(args []string) error {
	doc := `Usage:
  calicoctl review unused-policies [options]

Options:
  -h --help                  Show this screen.
  -t --time=<duration>       Time window to check for activity [default: 90d].
  -o --output=<format>       Output format: json or ps [default: ps].
     --server=<url>          Voltron/manager address (or CALICO_MANAGER_ADDRESS env).
     --token=<value>         Bearer token for authentication (or SERVICE_ACCOUNT_TOKEN env).
     --token-file=<path>     Path to file containing the bearer token.
     --skip-tls-verify       Skip TLS certificate verification (not recommended for production).

Description:
  Lists policies and rules that have not been evaluated within the specified
  time window. Use -t to set the lookback duration (e.g., 30d, 90d, 1y).

  Authentication is required. Provide a bearer token via --token-file (recommended),
  --token, or the SERVICE_ACCOUNT_TOKEN environment variable.`

	parser := &docopt.Parser{
		HelpHandler:   docopt.PrintHelpAndExit,
		OptionsFirst:  false,
		SkipHelpFlags: false,
	}
	arguments, err := parser.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}

	server, err := resolveServer(arguments)
	if err != nil {
		return err
	}

	token, err := resolveToken(arguments)
	if err != nil {
		return err
	}

	durationStr := "90d"
	if v, ok := arguments["--time"]; ok && v != nil {
		durationStr = v.(string)
	}
	// Convert shorthand durations (e.g. "90d") to relative format for timeutils.
	relStr := "now-" + durationStr
	now := time.Now().UTC()
	fromPtr, _, err := timeutils.ParseTime(now, &relStr)
	if err != nil {
		return fmt.Errorf("invalid time duration %q: %w", durationStr, err)
	}
	from := *fromPtr

	outputFmt := "ps"
	if v, ok := arguments["--output"]; ok && v != nil {
		outputFmt = v.(string)
	}
	if outputFmt != "json" && outputFmt != "ps" {
		return fmt.Errorf("invalid output format %q: must be 'json' or 'ps'", outputFmt)
	}

	skipTLS := false
	if v, ok := arguments["--skip-tls-verify"]; ok && v != nil {
		skipTLS = v.(bool)
	}

	resp, err := fetchUnusedPolicies(server, token, &from, &now, skipTLS)
	if err != nil {
		return err
	}

	switch outputFmt {
	case "json":
		return printJSON(resp)
	case "ps":
		return printText(resp)
	}
	return nil
}

// resolveServer resolves the manager/voltron server address from flags or env.
func resolveServer(arguments docopt.Opts) (string, error) {
	if v, ok := arguments["--server"]; ok && v != nil {
		return v.(string), nil
	}
	if v := os.Getenv("CALICO_MANAGER_ADDRESS"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no server address specified; use --server or set CALICO_MANAGER_ADDRESS")
}

// resolveToken resolves the bearer token from flags or env.
// Precedence: --token-file > --token > env var(SERVICE_ACCOUNT_TOKEN).
func resolveToken(arguments docopt.Opts) (string, error) {
	if v, ok := arguments["--token-file"]; ok && v != nil {
		data, err := os.ReadFile(v.(string))
		if err != nil {
			return "", fmt.Errorf("failed to read token file %q: %w", v.(string), err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if v, ok := arguments["--token"]; ok && v != nil {
		return v.(string), nil
	}

	if v := os.Getenv("SERVICE_ACCOUNT_TOKEN"); v != "" {
		return v, nil
	}

	return "", fmt.Errorf("no authentication token specified; use --token-file, --token, or set SERVICE_ACCOUNT_TOKEN")
}

// fetchUnusedPolicies calls the /policies/unused endpoint on the manager.
func fetchUnusedPolicies(server, token string, from, to *time.Time, skipTLS bool) (*v1.UnusedPoliciesResponse, error) {
	params := url.Values{}
	if from != nil {
		params.Set("from", from.UTC().Format(time.RFC3339))
	}
	if to != nil {
		params.Set("to", to.UTC().Format(time.RFC3339))
	}

	reqURL := strings.TrimRight(server, "/") + "/tigera-elasticsearch/policies/unused"
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLS, //nolint:gosec // Controlled by --skip-tls-verify flag.
			},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s: %s", resp.Status, string(body))
	}

	var result v1.UnusedPoliciesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// printJSON outputs the response as pretty-printed JSON.
func printJSON(resp *v1.UnusedPoliciesResponse) error {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// printText outputs the response as human-readable tables.
func printText(resp *v1.UnusedPoliciesResponse) error {
	printWarnings(resp)

	// Print unused policies table.
	fmt.Printf("Unused Policies (%d)\n", len(resp.Policies))
	if len(resp.Policies) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "KIND\tNAMESPACE\tNAME\tGENERATION")
		for _, p := range resp.Policies {
			ns := p.Namespace
			if ns == "" {
				ns = "N/A"
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", p.Kind, ns, p.Name, p.Generation)
		}
		_ = w.Flush()
	}

	fmt.Println()

	// Print unused rules table.
	fmt.Printf("Unused Rules (%d)\n", countUnusedRules(resp.Rules))
	if len(resp.Rules) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "KIND\tNAMESPACE\tNAME\tGENERATION\tDIRECTION\tINDEX")
		for _, r := range resp.Rules {
			ns := r.Namespace
			if ns == "" {
				ns = "N/A"
			}
			for _, rule := range r.UnusedRules {
				dir := rule.Direction
				if len(dir) > 0 {
					dir = strings.ToUpper(dir[:1]) + dir[1:]
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
					r.Kind, ns, r.Name, r.Generation,
					dir, rule.Index)
			}
		}
		_ = w.Flush()
	}

	return nil
}

// printWarnings prints warning banners if applicable.
func printWarnings(resp *v1.UnusedPoliciesResponse) {
	for _, p := range resp.Policies {
		if p.EvaluatedAtPreviousGeneration {
			fmt.Println("WARNING: Previous generations evaluated policy detected!")
			fmt.Println("  Some policies appear unused at their current generation but had")
			fmt.Println("  activity at a previous generation. These policies may have been")
			fmt.Println("  recently updated and could still be in active use.")
			fmt.Println()
			return
		}
	}
}

// countUnusedRules counts the total number of individual unused rules across all entries.
func countUnusedRules(entries []v1.UnusedRuleEntry) int {
	count := 0
	for _, e := range entries {
		count += len(e.UnusedRules)
	}
	return count
}
