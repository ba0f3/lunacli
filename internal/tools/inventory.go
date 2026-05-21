package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const inventorySchemaVersion = "luna.inventory.v1"

type inventoryCommand struct {
	name    string
	command string
	parse   func(*InventoryScanResult, string)
}

func registerScanHostInventory(s *server.MCPServer, pool *ssh.Pool) {
	tool := mcp.NewTool("scan_host_inventory",
		mcp.WithDescription(`Run a fixed read-only inventory scan on a remote Linux host via SSH.

Collects OS identity, packages, services, processes, listening ports, containers,
and Wazuh agent hints when available. The tool does not write remote state and
redacts secret-like process arguments before returning JSON.`),
		mcp.WithString("host",
			mcp.Required(),
			mcp.Description("Target host in format [user@]hostname[:port]"),
		),
		mcp.WithNumber("timeout_sec",
			mcp.Description("Per-collector timeout in seconds (default: 30, max: 300)"),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host, err := req.RequireString("host")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		timeoutSec := req.GetFloat("timeout_sec", 30)
		if timeoutSec <= 0 || timeoutSec > 300 {
			timeoutSec = 30
		}

		result := runInventoryScan(pool, host, time.Duration(timeoutSec*float64(time.Second)))
		payload, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("scan_host_inventory marshal error: %v", err)), nil
		}
		return mcp.NewToolResultText(string(payload)), nil
	})
}

func runInventoryScan(pool *ssh.Pool, host string, timeout time.Duration) InventoryScanResult {
	result := InventoryScanResult{
		SchemaVersion: inventorySchemaVersion,
		Host:          host,
		ScannedAt:     time.Now().UTC().Format(time.RFC3339),
		Identity:      HostIdentity{OSRelease: map[string]string{}},
	}

	for _, collector := range inventoryCollectors() {
		log.Printf("scan_host_inventory host=%s collector=%s", host, collector.name)
		execResult, err := pool.Execute(host, collector.command, timeout)
		record := InventoryCollector{Name: collector.name, Command: collector.command}
		if err != nil {
			record.ExitCode = -1
			record.Error = err.Error()
			result.Collectors = append(result.Collectors, record)
			continue
		}

		record.ExitCode = execResult.ExitCode
		if strings.TrimSpace(execResult.Stderr) != "" {
			record.Error = strings.TrimSpace(execResult.Stderr)
		}
		result.Collectors = append(result.Collectors, record)

		if execResult.ExitCode == 0 && collector.parse != nil {
			collector.parse(&result, execResult.Stdout)
		}
	}

	return result
}

func inventoryCollectors() []inventoryCommand {
	return []inventoryCommand{
		{
			name:    "hostname",
			command: "hostname",
			parse:   func(r *InventoryScanResult, out string) { r.Identity.Hostname = strings.TrimSpace(out) },
		},
		{
			name:    "os_release",
			command: "cat /etc/os-release",
			parse:   func(r *InventoryScanResult, out string) { r.Identity.OSRelease = parseOSRelease(out) },
		},
		{
			name:    "kernel",
			command: "uname -srmo",
			parse:   func(r *InventoryScanResult, out string) { r.Identity.Kernel = strings.TrimSpace(out) },
		},
		{
			name:    "architecture",
			command: "uname -m",
			parse:   func(r *InventoryScanResult, out string) { r.Identity.Architecture = strings.TrimSpace(out) },
		},
		{
			name:    "uptime",
			command: "uptime -p",
			parse:   func(r *InventoryScanResult, out string) { r.Identity.Uptime = strings.TrimSpace(out) },
		},
		{
			name:    "dpkg_packages",
			command: "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n'",
			parse:   func(r *InventoryScanResult, out string) { r.Packages = append(r.Packages, parseDPKGPackages(out)...) },
		},
		{
			name:    "rpm_packages",
			command: "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'",
			parse:   func(r *InventoryScanResult, out string) { r.Packages = append(r.Packages, parseRPMPackages(out)...) },
		},
		{
			name:    "apk_packages",
			command: "apk info -vv",
			parse:   func(r *InventoryScanResult, out string) { r.Packages = append(r.Packages, parseAPKPackages(out)...) },
		},
		{
			name:    "systemd_services",
			command: "systemctl list-units --type=service --all --no-legend --no-pager --plain",
			parse: func(r *InventoryScanResult, out string) {
				r.Services = append(r.Services, parseSystemdServices(out)...)
			},
		},
		{
			name:    "processes",
			command: "ps -eo user=,pid=,pcpu=,pmem=,args= --no-headers",
			parse:   func(r *InventoryScanResult, out string) { r.Processes = append(r.Processes, parsePSProcesses(out)...) },
		},
		{
			name:    "ports",
			command: "ss -H -tulpen",
			parse:   func(r *InventoryScanResult, out string) { r.Ports = append(r.Ports, parseSSPorts(out)...) },
		},
		{
			name:    "docker_containers",
			command: "docker ps -a --format '{{.ID}}\\t{{.Image}}\\t{{.Names}}\\t{{.Status}}'",
			parse: func(r *InventoryScanResult, out string) {
				r.Containers = append(r.Containers, parseDockerContainers(out)...)
			},
		},
		{
			name:    "wazuh_client_keys",
			command: "awk '{print $1, $2}' /var/ossec/etc/client.keys",
			parse:   func(r *InventoryScanResult, out string) { r.Wazuh = parseWazuhClientKeys(out) },
		},
	}
}
