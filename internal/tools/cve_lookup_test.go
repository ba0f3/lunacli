package tools

import (
	"fmt"
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

func TestFetchMITRECVELookupParsesBasicFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/CVE-2026-9256" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "dataType": "CVE_RECORD",
		  "cveMetadata": {
		    "cveId": "CVE-2026-9256",
		    "datePublished": "2026-05-22T14:11:41.877Z",
		    "dateUpdated": "2026-05-22T14:50:36.484Z"
		  },
		  "containers": {
		    "cna": {
		      "descriptions": [{"lang": "en", "value": "NGINX rewrite module heap overflow."}],
		      "references": [{"url": "https://my.f5.com/manage/s/article/K000161377"}],
		      "metrics": [{
		        "format": "CVSS",
		        "cvssV3_1": {
		          "baseScore": 8.1,
		          "baseSeverity": "HIGH",
		          "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
		        }
		      }]
		    }
		  }
		}`))
	}))
	defer server.Close()

	got, err := fetchMITRECVELookup(server.URL, "CVE-2026-9256", server.Client())
	if err != nil {
		t.Fatalf("fetchMITRECVELookup error: %v", err)
	}
	if got.Source != "mitre" || got.ID != "CVE-2026-9256" {
		t.Fatalf("unexpected id/source: %+v", got)
	}
	if got.Severity != "HIGH" || got.CVSSScore != 8.1 || len(got.References) != 1 {
		t.Fatalf("unexpected lookup: %+v", got)
	}
	if got.Summary == "" {
		t.Fatal("expected summary")
	}
}

func TestFetchMITRECVELookupHandlesHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer server.Close()

	_, err := fetchMITRECVELookup(server.URL, "CVE-2026-9256", server.Client())
	if err == nil {
		t.Fatal("expected error")
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

func TestLookupCVEPrefersMITREOverNVD(t *testing.T) {
	var nvdCalled bool
	mitre := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
		  "dataType": "CVE_RECORD",
		  "cveMetadata": {"cveId": "CVE-2026-9256", "datePublished": "2026-05-22T14:11:41.877Z"},
		  "containers": {"cna": {"descriptions": [{"lang": "en", "value": "from mitre"}]}}
		}`))
	}))
	defer mitre.Close()

	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nvdCalled = true
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-9256","descriptions":[{"lang":"en","value":"from nvd"}]}}]}`))
	}))
	defer nvd.Close()

	client := mitre.Client()
	got := lookupCVEWithURLs("CVE-2026-9256", client, mitre.URL, nvd.URL)
	if got.Source != "mitre" || got.Summary != "from mitre" {
		t.Fatalf("got %+v, want mitre source", got)
	}
	if nvdCalled {
		t.Fatal("NVD should not be called when MITRE succeeds")
	}
}

func TestLookupCVEFallsBackToNVDWhenMITREMissing(t *testing.T) {
	mitre := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer mitre.Close()

	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
		  "vulnerabilities": [{
		    "cve": {
		      "id": "CVE-2024-3094",
		      "descriptions": [{"lang":"en","value":"from nvd"}],
		      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString":"CVSS:3.1/AV:N"}}]}
		    }
		  }]
		}`))
	}))
	defer nvd.Close()

	got := lookupCVEWithURLs("CVE-2024-3094", mitre.Client(), mitre.URL, nvd.URL)
	if got.Source != "nvd" || got.Summary != "from nvd" {
		t.Fatalf("got %+v, want nvd fallback", got)
	}
	if len(got.Errors) == 0 || got.Errors[0] == "" {
		t.Fatalf("expected mitre error in Errors: %+v", got.Errors)
	}
}

// lookupCVEWithURLs is a test hook for configurable API bases.
func lookupCVEWithURLs(cveID string, client *http.Client, mitreBase, nvdBase string) CVELookupResult {
	result, mitreErr := fetchMITRECVELookup(mitreBase, cveID, client)
	if mitreErr == nil {
		return result
	}

	result, err := fetchNVDLookup(nvdBase, cveID, client)
	if err != nil {
		return CVELookupResult{
			SchemaVersion: "luna.cve.v1",
			ID:            cveID,
			Source:        "nvd",
			Errors:        []string{fmt.Sprintf("mitre: %v", mitreErr), fmt.Sprintf("nvd: %v", err)},
		}
	}
	if mitreErr != nil {
		result.Errors = append([]string{fmt.Sprintf("mitre: %v", mitreErr)}, result.Errors...)
	}
	return result
}
