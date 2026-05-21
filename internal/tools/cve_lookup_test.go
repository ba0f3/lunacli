package tools

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateCVEID(t *testing.T) {
	valid := []string{"CVE-2024-3094", "cve-2026-42945"}
	for _, id := range valid {
		got, ok := normalizeCVEID(id)
		if !ok || got[:4] != "CVE-" {
			t.Fatalf("normalizeCVEID(%q) = %q, %v", id, got, ok)
		}
	}
	if _, ok := normalizeCVEID("not-a-cve"); ok {
		t.Fatal("expected invalid CVE to fail")
	}
}

func TestFetchNVDLookupParsesBasicFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
		  "vulnerabilities": [{
		    "cve": {
		      "id": "CVE-2024-3094",
		      "published": "2024-03-29T00:00:00.000",
		      "lastModified": "2024-04-01T00:00:00.000",
		      "descriptions": [{"lang":"en","value":"Backdoor in xz utils."}],
		      "references": {"referenceData": [{"url":"https://example.test/advisory"}]},
		      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString":"CVSS:3.1/AV:N/AC:L"}}]}
		    }
		  }]
		}`))
	}))
	defer server.Close()

	got, err := fetchNVDLookup(server.URL, "CVE-2024-3094", server.Client())
	if err != nil {
		t.Fatalf("fetchNVDLookup error: %v", err)
	}
	if got.ID != "CVE-2024-3094" || got.Severity != "CRITICAL" || got.CVSSScore != 10.0 || len(got.References) != 1 {
		t.Fatalf("unexpected lookup: %+v", got)
	}
}

func TestFetchNVDLookupHandlesHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer server.Close()

	_, err := fetchNVDLookup(server.URL, "CVE-2024-3094", server.Client())
	if err == nil {
		t.Fatal("expected error")
	}
}
