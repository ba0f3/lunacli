package ssh

import (
	"sort"
	"testing"
)

func TestDiscoverKnownHostNames_tailscalePeer(t *testing.T) {
	if len(tailscaleHostCandidates()) == 0 {
		t.Skip("tailscale not available")
	}
	found := false
	for _, name := range tailscaleHostCandidates() {
		if name == "r2d-infra" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tailscaleHostCandidates() missing r2d-infra: %v", tailscaleHostCandidates())
	}

	hosts, err := ParseKnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(hosts)
	if !containsString(hosts, "r2d-infra") {
		t.Fatalf("ParseKnownHosts() = %v, want r2d-infra", hosts)
	}
}
