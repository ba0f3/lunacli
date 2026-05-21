package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerListHosts(s *server.MCPServer) {
	tool := mcp.NewTool("list_hosts",
		mcp.WithDescription(`List unhashed hostnames extracted from ~/.ssh/known_hosts.
Use this before execute_remote to find available hosts.
Credentials and keys are managed by your local SSH agent.`),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		hosts, err := ssh.ParseKnownHosts()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to read known_hosts: %v", err)), nil
		}

		if len(hosts) == 0 {
			return mcp.NewToolResultText("No unhashed hosts found in ~/.ssh/known_hosts."), nil
		}

		sort.Strings(hosts)

		var b strings.Builder
		b.WriteString("Available Hosts (from ~/.ssh/known_hosts):\n")
		b.WriteString(strings.Repeat("─", 50) + "\n")

		for _, host := range hosts {
			b.WriteString(fmt.Sprintf("- %s\n", host))
		}

		b.WriteString(fmt.Sprintf("\nTotal: %d unhashed host(s)\n", len(hosts)))
		return mcp.NewToolResultText(b.String()), nil
	})
}
