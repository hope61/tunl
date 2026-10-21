package cmd

import (
	"fmt"
	"os"
	"os/user"
	"runtime"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tunl",
	Short: "Expose ports from a home server to the internet through a VPS over WireGuard",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("tunl only runs on Linux")
		}
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("checking user: %w", err)
		}
		if u.Uid != "0" {
			return fmt.Errorf("tunl must be run as root (or with CAP_NET_ADMIN)")
		}
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
