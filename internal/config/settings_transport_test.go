package config

import "testing"

func TestTransportMode_DefaultProxy(t *testing.T) {
	s := &Settings{file: FileSettings{}}
	if got := s.TransportMode(); got != "proxy" {
		t.Fatalf("TransportMode() = %q, want proxy", got)
	}
}

func TestTransportMode_EnvOverride(t *testing.T) {
	t.Setenv("LUNA_TRANSPORT_MODE", "direct")
	s := &Settings{file: FileSettings{Transport: TransportSettings{Mode: "proxy"}}}
	if got := s.TransportMode(); got != "direct" {
		t.Fatalf("TransportMode() = %q, want direct", got)
	}
}

func TestProxyEndpoint_RequiredFields(t *testing.T) {
	s := &Settings{file: FileSettings{Transport: TransportSettings{Mode: "proxy"}}}
	if ep := s.ProxyEndpoint(); ep != "" {
		t.Fatalf("ProxyEndpoint() = %q, want empty", ep)
	}
	t.Setenv("LUNA_PROXY_ENDPOINT", "https://proxy.test")
	if ep := s.ProxyEndpoint(); ep != "https://proxy.test" {
		t.Fatalf("ProxyEndpoint() = %q", ep)
	}
}
