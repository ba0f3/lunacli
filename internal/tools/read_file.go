package tools

import (
	"context"
	"fmt"
	"log"

	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const defaultMaxKB = 100

func registerReadFile(s *server.MCPServer, pool *ssh.Pool) {
	tool := mcp.NewTool("read_file",
		mcp.WithDescription(`Read a file from a remote host via SFTP (read-only).
Use this to inspect config files, logs, or any text file on the remote system.
File size is capped by max_kb to prevent accidental large transfers.`),
		mcp.WithString("host",
			mcp.Required(),
			mcp.Description("Target host in format [user@]hostname[:port] (e.g. ubuntu@192.168.1.50)"),
		),
		mcp.WithString("path",
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
		path, err := req.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		maxKB := int64(req.GetFloat("max_kb", defaultMaxKB))
		if maxKB <= 0 || maxKB > 1024 {
			maxKB = defaultMaxKB
		}
		maxBytes := maxKB * 1024

		log.Printf("read_file host=%s path=%q max_kb=%d", host, path, maxKB)

		content, err := pool.ReadFile(host, path, maxBytes)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("read_file error: %v", err)), nil
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
			host, path, len(content), string(content), truncated,
		)), nil
	})
}
