package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
	"github.com/ba0f3/lunacli/internal/engine"
	"github.com/ba0f3/lunacli/internal/policy"
	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:   "exec [host] [command]",
	Short: "Execute a remote command directly with policy check",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		command := args[1]

		settings, err := config.LoadSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(1)
		}

		pol, err := policy.LoadPolicy(settings.ConfigDir())
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy required: %v\n", err)
			os.Exit(1)
		}

		eng := engine.NewEngine(pol)
		res := eng.Classify(command, host, nil)

		if res.Class == engine.Forbidden {
			fmt.Fprintf(os.Stderr, "Command Blocked: %s\n", res.Reason)
			os.Exit(1)
		}

		if res.Class == engine.Mutating {
			fmt.Fprintf(os.Stderr, "Mutating command requires approval: %s\n", res.Reason)
			os.Exit(1)
		}

		pool := ssh.NewPool()
		execRes, err := pool.Execute(host, command, 30*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SSH error: %v\n", err)
			os.Exit(1)
		}

		fmt.Print(execRes.Stdout)
		if execRes.Stderr != "" {
			fmt.Fprintln(os.Stderr, execRes.Stderr)
		}
		os.Exit(execRes.ExitCode)
	},
}

func init() {
	RootCmd.AddCommand(execCmd)
}
