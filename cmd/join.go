package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hope61/tunl/internal/config"
	"github.com/hope61/tunl/internal/netsetup"
	"github.com/hope61/tunl/internal/systemd"
	"github.com/hope61/tunl/internal/token"
)

var joinCmd = &cobra.Command{
	Use:   "join <token>",
	Short: "Join a server using a join token (run on home machine)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		tok, err := token.Decode(args[0])
		if err != nil {
			return err
		}

		privKey, pubKey, err := netsetup.GenerateKeyPair()
		if err != nil {
			return err
		}

		cfg := &config.Config{
			Role:       config.RoleAgent,
			Interface:  tok.Interface,
			MTU:        tok.MTU,
			PrivateKey: privKey,
			PublicKey:  pubKey,
			PeerPubKey: tok.ServerPub,
			Endpoint:   tok.Endpoint,
			TunnelAddr: tok.AgentAddr,
			PeerAddr:   tok.ServerAddr,
			Subnet:     tok.Subnet,
		}

		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}

		if err := config.Save(config.DefaultPath(), cfg); err != nil {
			return err
		}

		if err := netsetup.Up(cfg); err != nil {
			return fmt.Errorf("applying config: %w", err)
		}

		if err := systemd.Install(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not install systemd unit: %v\n", err)
		}

		fmt.Println("Agent configured. Now run this on the server to authorize:")
		fmt.Printf("  tunl server allow %s\n", pubKey)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(joinCmd)
}
