package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hope61/tunl/internal/config"
	"github.com/hope61/tunl/internal/netsetup"
	"github.com/hope61/tunl/internal/systemd"
	"github.com/hope61/tunl/internal/token"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Server (VPS) commands",
}

var serverInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the server and generate a join token",
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		endpoint, _ := cmd.Flags().GetString("endpoint")
		iface, _ := cmd.Flags().GetString("interface")
		listenPort, _ := cmd.Flags().GetInt("listen-port")
		subnet, _ := cmd.Flags().GetString("subnet")
		mtu, _ := cmd.Flags().GetInt("mtu")

		endpoint, err = config.ValidateEndpoint(endpoint)
		if err != nil {
			return err
		}

		privKey, pubKey, err := netsetup.GenerateKeyPair()
		if err != nil {
			return err
		}

		cfg := &config.Config{
			Role:       config.RoleServer,
			Interface:  iface,
			MTU:        mtu,
			PrivateKey: privKey,
			PublicKey:  pubKey,
			Endpoint:   endpoint,
			ListenPort: listenPort,
			TunnelAddr: config.DefaultServerIP,
			PeerAddr:   config.DefaultAgentIP,
			Subnet:     subnet,
		}

		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}

		if err := config.Save(config.DefaultPath(), cfg); err != nil {
			return err
		}

		tok, err := token.Encode(pubKey, endpoint, config.DefaultServerIP, config.DefaultAgentIP, subnet, iface, mtu, listenPort)
		if err != nil {
			return err
		}

		if err := netsetup.Up(cfg); err != nil {
			return fmt.Errorf("applying config: %w", err)
		}

		if err := systemd.Install(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not install systemd unit: %v\n", err)
		}

		fmt.Println("Server initialized successfully.")
		fmt.Println()
		fmt.Printf("IMPORTANT: Ensure UDP port %d is open in your cloud provider's firewall/security group.\n", listenPort)
		fmt.Printf("           tunl handles OS-level firewalls (ufw) automatically, but cloud firewalls\n")
		fmt.Printf("           (AWS Security Groups, DigitalOcean/Hetzner Firewalls, etc.) must be\n")
		fmt.Printf("           configured through your provider's dashboard or API.\n")
		fmt.Println()
		fmt.Println("Join token (run this on the home machine):")
		fmt.Printf("  tunl join %s\n", tok)
		fmt.Println()
		fmt.Println("After the agent joins, authorize it with:")
		fmt.Println("  tunl server allow <agent-public-key>")

		return nil
	},
}

var serverAllowCmd = &cobra.Command{
	Use:   "allow <agent-public-key>",
	Short: "Authorize an agent by its public key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		agentKey := args[0]
		if err := config.ValidateWGKey(agentKey); err != nil {
			return fmt.Errorf("invalid agent key: %w", err)
		}

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}
		if cfg.Role != config.RoleServer {
			return fmt.Errorf("this machine is configured as %s, not server", cfg.Role)
		}

		cfg.AllowedAgentKey = agentKey
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}

		if err := config.Save(config.DefaultPath(), cfg); err != nil {
			return err
		}

		if err := netsetup.Up(cfg); err != nil {
			return fmt.Errorf("applying config: %w", err)
		}

		fmt.Println("Agent authorized. The tunnel should come up shortly.")
		return nil
	},
}

func init() {
	serverInitCmd.Flags().String("endpoint", "", "Public endpoint (host:port) for WireGuard")
	serverInitCmd.MarkFlagRequired("endpoint")
	serverInitCmd.Flags().String("interface", config.DefaultInterface, "WireGuard interface name")
	serverInitCmd.Flags().Int("listen-port", config.DefaultPort, "WireGuard UDP listen port")
	serverInitCmd.Flags().String("subnet", config.DefaultSubnet, "Tunnel subnet")
	serverInitCmd.Flags().Int("mtu", config.DefaultMTU, "Interface MTU")

	serverCmd.AddCommand(serverInitCmd, serverAllowCmd)
	rootCmd.AddCommand(serverCmd)
}
