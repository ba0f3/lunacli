package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	mitreCVEAPI = "https://cveawg.mitre.org/api/cve"
	nvdCVEAPI   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

var cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

type CVELookupResult struct {
	SchemaVersion string   `json:"schema_version"`
	ID            string   `json:"id"`
	Source        string   `json:"source"`
	Summary       string   `json:"summary,omitempty"`
	Published     string   `json:"published,omitempty"`
	LastModified  string   `json:"last_modified,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	CVSSScore     float64  `json:"cvss_score,omitempty"`
	CVSSVector    string   `json:"cvss_vector,omitempty"`
	References    []string `json:"references,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

func registerLookupCVE(s *server.MCPServer) {
	tool := mcp.NewTool("lookup_cve",
		mcp.WithDescription("Look up a CVE from external advisory sources and return normalized JSON advisory evidence. Tries the MITRE CVE API first, then NVD."),
		mcp.WithString("cve_id",
			mcp.Required(),
			mcp.Description("CVE ID such as CVE-2024-3094"),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		raw, err := req.RequireString("cve_id")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		cveID, ok := normalizeCVEID(raw)
		if !ok {
			errorResult := map[string]interface{}{
				"error":   "INVALID_CVE_ID",
				"message": fmt.Sprintf("%q is not a valid CVE identifier", raw),
				"raw":     raw,
			}
			payload, _ := json.MarshalIndent(errorResult, "", "  ")
			return mcp.NewToolResultText(string(payload)), nil
		}

		client := &http.Client{Timeout: 20 * time.Second}
		result := lookupCVE(ctx, cveID, client)
		payload, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("lookup_cve marshal error: %v", err)), nil
		}
		return mcp.NewToolResultText(string(payload)), nil
	})
}

func normalizeCVEID(raw string) (string, bool) {
	if len(raw) > 50 {
		return "", false
	}
	id := strings.ToUpper(strings.TrimSpace(raw))
	return id, cveIDPattern.MatchString(id)
}

func lookupCVE(ctx context.Context, cveID string, client *http.Client) CVELookupResult {
	result, mitreErr := fetchMITRECVELookup(ctx, mitreCVEAPI, cveID, client)
	if mitreErr == nil {
		return result
	}

	result, err := fetchNVDLookup(ctx, nvdCVEAPI, cveID, client)
	if err != nil {
		errs := []string{fmt.Sprintf("mitre: %v", mitreErr), fmt.Sprintf("nvd: %v", err)}
		return CVELookupResult{
			SchemaVersion: "luna.cve.v1",
			ID:            cveID,
			Source:        "nvd",
			Errors:        errs,
		}
	}
	if mitreErr != nil {
		result.Errors = append([]string{fmt.Sprintf("mitre: %v", mitreErr)}, result.Errors...)
	}
	return result
}

func fetchMITRECVELookup(ctx context.Context, baseURL, cveID string, client *http.Client) (CVELookupResult, error) {
	endpoint := strings.TrimSuffix(baseURL, "/") + "/" + cveID
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return CVELookupResult{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return CVELookupResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return CVELookupResult{}, fmt.Errorf("MITRE CVE API returned no record for %s", cveID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CVELookupResult{}, fmt.Errorf("MITRE CVE API lookup failed with HTTP %d", resp.StatusCode)
	}

	var payload mitreCVERecord
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<20)).Decode(&payload); err != nil {
		return CVELookupResult{}, err
	}
	if payload.DataType != "CVE_RECORD" || payload.CVEMetadata.CVEID == "" {
		return CVELookupResult{}, fmt.Errorf("MITRE CVE API returned unexpected record for %s", cveID)
	}

	result := CVELookupResult{
		SchemaVersion: "luna.cve.v1",
		ID:            payload.CVEMetadata.CVEID,
		Source:        "mitre",
		Published:     payload.CVEMetadata.DatePublished,
		LastModified:  payload.CVEMetadata.DateUpdated,
	}
	cna := payload.Containers.CNA
	for _, desc := range cna.Descriptions {
		if desc.Lang == "en" && desc.Value != "" {
			result.Summary = desc.Value
			break
		}
	}
	setMITRECVSSFields(&result, cna.Metrics)
	for _, ref := range cna.References {
		if ref.URL != "" {
			result.References = append(result.References, ref.URL)
		}
	}
	return result, nil
}

func setMITRECVSSFields(result *CVELookupResult, metrics []mitreCVSSMetric) {
	for _, m := range metrics {
		if m.Format != "CVSS" {
			continue
		}
		if m.CVSSV31 != nil {
			result.CVSSScore = m.CVSSV31.BaseScore
			result.Severity = strings.ToUpper(m.CVSSV31.BaseSeverity)
			result.CVSSVector = m.CVSSV31.VectorString
			return
		}
	}
	for _, m := range metrics {
		if m.Format != "CVSS" || m.CVSSV40 == nil {
			continue
		}
		result.CVSSScore = m.CVSSV40.BaseScore
		result.Severity = strings.ToUpper(m.CVSSV40.BaseSeverity)
		result.CVSSVector = m.CVSSV40.VectorString
		return
	}
}

type mitreCVERecord struct {
	DataType    string `json:"dataType"`
	CVEMetadata struct {
		CVEID         string `json:"cveId"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA mitreCNABlock `json:"cna"`
	} `json:"containers"`
}

type mitreCNABlock struct {
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Metrics []mitreCVSSMetric `json:"metrics"`
}

type mitreCVSSMetric struct {
	Format  string          `json:"format"`
	CVSSV31 *mitreCVSSScore `json:"cvssV3_1"`
	CVSSV40 *mitreCVSSScore `json:"cvssV4_0"`
}

type mitreCVSSScore struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

func fetchNVDLookup(ctx context.Context, baseURL, cveID string, client *http.Client) (CVELookupResult, error) {
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		return CVELookupResult{}, err
	}
	q := endpoint.Query()
	q.Set("cveId", cveID)
	endpoint.RawQuery = q.Encode()

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return CVELookupResult{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return CVELookupResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CVELookupResult{}, fmt.Errorf("NVD lookup failed with HTTP %d", resp.StatusCode)
	}

	var payload nvdResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<20)).Decode(&payload); err != nil {
		return CVELookupResult{}, err
	}
	if len(payload.Vulnerabilities) == 0 {
		return CVELookupResult{}, fmt.Errorf("NVD returned no records for %s", cveID)
	}

	cve := payload.Vulnerabilities[0].CVE
	result := CVELookupResult{
		SchemaVersion: "luna.cve.v1",
		ID:            cve.ID,
		Source:        "nvd",
		Published:     cve.Published,
		LastModified:  cve.LastModified,
	}
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			result.Summary = desc.Value
			break
		}
	}
	setCVSSFields(&result, cve)
	for _, ref := range cve.References.ReferenceData {
		if ref.URL != "" {
			result.References = append(result.References, ref.URL)
		}
	}
	return result, nil
}

func setCVSSFields(result *CVELookupResult, cve nvdCVE) {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		data := cve.Metrics.CVSSMetricV31[0].CVSSData
		result.CVSSScore = data.BaseScore
		result.Severity = data.BaseSeverity
		result.CVSSVector = data.VectorString
		return
	}
	if len(cve.Metrics.CVSSMetricV30) > 0 {
		data := cve.Metrics.CVSSMetricV30[0].CVSSData
		result.CVSSScore = data.BaseScore
		result.Severity = data.BaseSeverity
		result.CVSSVector = data.VectorString
		return
	}
	if len(cve.Metrics.CVSSMetricV2) > 0 {
		data := cve.Metrics.CVSSMetricV2[0].CVSSData
		result.CVSSScore = data.BaseScore
		result.Severity = cve.Metrics.CVSSMetricV2[0].BaseSeverity
		result.CVSSVector = data.VectorString
	}
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References struct {
		ReferenceData []struct {
			URL string `json:"url"`
		} `json:"referenceData"`
	} `json:"references"`
	Metrics struct {
		CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
		CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
		CVSSMetricV2  []struct {
			CVSSData     nvdCVSSData `json:"cvssData"`
			BaseSeverity string      `json:"baseSeverity"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}
