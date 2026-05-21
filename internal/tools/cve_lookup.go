package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const nvdCVEAPI = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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
		mcp.WithDescription("Look up a CVE from external advisory sources and return normalized JSON advisory evidence."),
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
		result, err := fetchNVDLookup(nvdCVEAPI, cveID, client)
		if err != nil {
			result = CVELookupResult{
				SchemaVersion: "luna.cve.v1",
				ID:            cveID,
				Source:        "nvd",
				Errors:        []string{err.Error()},
			}
		}
		payload, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("lookup_cve marshal error: %v", err)), nil
		}
		return mcp.NewToolResultText(string(payload)), nil
	})
}

func normalizeCVEID(raw string) (string, bool) {
	id := strings.ToUpper(strings.TrimSpace(raw))
	return id, cveIDPattern.MatchString(id)
}

func fetchNVDLookup(baseURL, cveID string, client *http.Client) (CVELookupResult, error) {
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		return CVELookupResult{}, err
	}
	q := endpoint.Query()
	q.Set("cveId", cveID)
	endpoint.RawQuery = q.Encode()

	resp, err := client.Get(endpoint.String())
	if err != nil {
		return CVELookupResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CVELookupResult{}, fmt.Errorf("NVD lookup failed with HTTP %d", resp.StatusCode)
	}

	var payload nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
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
