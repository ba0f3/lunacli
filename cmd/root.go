package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "luna",
	Short: "Luna: Zero-trust secure remote SSH agent and stdio MCP server",
}

func Execute() {
	// Default to stdio MCP when invoked with no subcommand (OpenCode / legacy entrypoints).
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "serve")
	}
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
