package onboard

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ba0f3/lunacli/internal/config"
)

func TestValidateProxyEndpoint(t *testing.T) {
	tests := []struct {
		in    string
		wantErr bool
	}{
		{"https://proxy.example:8443", false},
		{"http://127.0.0.1:8443", false},
		{"", true},
		{"not-a-url", true},
		{"ftp://proxy.example", true},
		{"https://", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			err := validateProxyEndpoint(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateProxyEndpoint(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestPromptTransport_proxyDefaultsTLS(t *testing.T) {
	in := strings.NewReader("\nhttps://proxy.example:8443\n2\n")
	var out, errOut bytes.Buffer
	p := NewPrompter(in, &out)

	ts, err := PromptTransport(p, &out, &errOut, config.TransportSettings{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if ts.Mode != "proxy" {
		t.Fatalf("Mode = %q, want proxy", ts.Mode)
	}
	if ts.Proxy.Endpoint != "https://proxy.example:8443" {
		t.Fatalf("Endpoint = %q", ts.Proxy.Endpoint)
	}
}

func TestPromptTransport_directMode(t *testing.T) {
	in := strings.NewReader("2\n")
	var out, errOut bytes.Buffer
	p := NewPrompter(in, &out)

	ts, err := PromptTransport(p, &out, &errOut, config.TransportSettings{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if ts.Mode != "direct" {
		t.Fatalf("Mode = %q, want direct", ts.Mode)
	}
	if !strings.Contains(errOut.String(), "warning:") {
		t.Fatalf("stderr = %q, want warning", errOut.String())
	}
}
