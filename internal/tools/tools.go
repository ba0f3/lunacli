package tools

import (
	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/engine"
	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/mark3labs/mcp-go/server"
)

// Register wires all luna MCP tools onto the server.
func Register(s *server.MCPServer, pool *ssh.Pool, eng *engine.Engine, gate *approval.Gate) {
	registerListHosts(s)
	registerExecuteRemote(s, pool, eng, gate)
	registerReadFile(s, pool)
	registerFetchRemoteFile(s, pool)
	registerScanHostInventory(s, pool)
	registerLookupCVE(s)
}
