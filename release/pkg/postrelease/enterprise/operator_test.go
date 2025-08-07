package enterprise

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-github/v53/github"

	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

func githubClient() *github.Client {
	cli := github.NewClient(http.DefaultClient)
	if githubToken != "" {
		cli = github.NewTokenClient(context.Background(), githubToken)
	}
	return cli
}

func TestOperatorGitHubRelease(t *testing.T) {
	t.Parallel()

	if skipOperator {
		t.Skip("Skipping Tigera Operator validation as per flag")
		return
	}

	checkVersion(t, operatorVersion)

	release, resp, err := githubClient().Repositories.GetReleaseByTag(context.Background(), operator.DefaultOrg, operator.DefaultRepoName, operatorVersion)
	if err != nil {
		t.Fatalf("failed to get %s release: %v", operatorVersion, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to get %s release: %v", operatorVersion, resp.Status)
	}

	if !strings.Contains(*release.Body, fmt.Sprintf("Calico Enterprise version: %s", releaseVersion)) {
		t.Fatalf("expected release desc to state Calico Enterprise version %s", releaseVersion)
	}
	if !strings.Contains(*release.Body, "Calico version:") {
		t.Fatalf("expected release desc to state Calico version")
	}
	t.Logf("Found Tigera Operator release %s for Calico Enterprise version %s", operatorVersion, releaseVersion)
}

func TestOperatorGitHubMilestone(t *testing.T) {
	t.Parallel()

	if skipOperator {
		t.Skip("Skipping Tigera Operator validation as per flag")
		return
	}

	checkVersion(t, operatorVersion)

	ver := version.New(operatorVersion)
	nextVer, err := ver.NextReleaseVersion()
	if err != nil {
		t.Fatalf("failed to get next operator release version: %v", err)
	}
	for _, tt := range []struct {
		milestone     string
		expectedState string
	}{
		{milestone: ver.FormattedString(), expectedState: "closed"},
		{milestone: nextVer.FormattedString(), expectedState: "open"},
	} {
		t.Run(tt.milestone, func(t *testing.T) {
			milestones, resp, err := githubClient().Issues.ListMilestones(context.Background(), operator.DefaultOrg, operator.DefaultRepoName, &github.MilestoneListOptions{
				State:     tt.expectedState,
				Direction: "desc",
				ListOptions: github.ListOptions{
					PerPage: 100,
					Page:    1,
				},
			})
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("failed to list milestones: %v", err)
			}
			selected := slices.Collect(func(yield func(*github.Milestone) bool) {
				for _, m := range milestones {
					if m.GetTitle() == tt.milestone {
						yield(m)
					}
				}
			})
			if len(selected) == 0 {
				t.Fatalf("failed to find %s milestone %s", tt.expectedState, tt.milestone)
			}
			actualState := selected[0].GetState()
			if actualState != tt.expectedState {
				t.Fatalf(`expected "%s" milestone to be %s but found %s`, tt.milestone, tt.expectedState, actualState)
			}
			t.Logf("Found %s milestone %s with state %s", tt.expectedState, tt.milestone, actualState)
		})
	}
}
