package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/config"
	"github.com/ba0f3/lunacli/internal/engine"
	"github.com/ba0f3/lunacli/internal/policy"
	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/ba0f3/lunacli/internal/tools"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the stdio MCP server",
	Run: func(cmd *cobra.Command, args []string) {
		log.SetOutput(os.Stderr)
		log.Printf("starting zero-trust secure stdio server")

		settings, err := config.LoadSettings()
		if err != nil {
			log.Fatalf("config: %v", err)
		}

		cfgDir := settings.ConfigDir()
		pol, err := policy.LoadPolicy(cfgDir)
		if err != nil {
			log.Fatalf("failed to load policy.yml (required): %v", err)
		}

		if err := settings.ValidateTransport(); err != nil {
			log.Fatalf("config: %v", err)
		}

		eng := engine.NewEngine(pol)
		pool, err := ssh.NewPool(settings)
		if err != nil {
			log.Fatalf("ssh: %v", err)
		}

		boot, err := approval.BootstrapServeApproval(settings)
		if err != nil {
			log.Fatalf("approval: %v", err)
		}
		defer boot.PollCancel()

		s := server.NewMCPServer(
			"luna", "2.0.0",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		)

		tools.Register(s, pool, eng, boot.Gate)
		if err := server.ServeStdio(s); err != nil {
			fmt.Fprintf(os.Stderr, "server runtime error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(serveCmd)
}
