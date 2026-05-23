package cmd

import (
	"os"

	"github.com/ba0f3/lunacli/internal/onboard"
	"github.com/spf13/cobra"
)

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Interactive setup for Luna config, policy, and Telegram",
	RunE: func(cmd *cobra.Command, args []string) error {
		return onboard.Run(os.Stdin, os.Stdout, os.Stderr)
	},
}

func init() {
	RootCmd.AddCommand(onboardCmd)
}
