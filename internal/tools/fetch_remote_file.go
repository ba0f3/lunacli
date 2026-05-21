package tools

import (
	"context"
	"fmt"
	"log"

	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerFetchRemoteFile(s *server.MCPServer, pool *ssh.Pool) {
	tool := mcp.NewTool("fetch_remote_file",
		mcp.WithDescription(`Fetch a file from a remote host via SFTP (read-only download).

Use this to retrieve config files, scripts, or other text content from the remote host.
File size is capped by max_kb to prevent accidental large transfers.`),
		mcp.WithString("host",
			mcp.Required(),
			mcp.Description("Target host in format [user@]hostname[:port] (e.g. ubuntu@192.168.1.50)"),
		),
		mcp.WithString("remote_path",
			mcp.Required(),
			mcp.Description("Absolute path of the file on the remote host (e.g. /etc/nginx/nginx.conf)"),
		),
		mcp.WithNumber("max_kb",
			mcp.Description(fmt.Sprintf("Maximum file size to read in KB (default: %d, max: 1024)", defaultMaxKB)),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host, err := req.RequireString("host")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		remotePath, err := req.RequireString("remote_path")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		maxKB := int64(req.GetFloat("max_kb", defaultMaxKB))
		if maxKB <= 0 || maxKB > 1024 {
			maxKB = defaultMaxKB
		}
		maxBytes := maxKB * 1024

		log.Printf("fetch_remote_file host=%s path=%q max_kb=%d", host, remotePath, maxKB)

		content, err := pool.ReadFile(host, remotePath, maxBytes)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("fetch_remote_file error: %v", err)), nil
		}

		truncated := ""
		if int64(len(content)) >= maxBytes {
			truncated = fmt.Sprintf(
				"\n\n[TRUNCATED — file exceeds %d KB limit; increase max_kb or use grep/tail for targeted reads]",
				maxKB,
			)
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"Host: %s\nPath: %s\nSize: %d bytes\n\n--- FILE CONTENT ---\n%s%s",
			host, remotePath, len(content), string(content), truncated,
		)), nil
	})
}
