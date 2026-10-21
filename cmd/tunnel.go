package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/hope61/tunl/internal/config"
	"github.com/hope61/tunl/internal/doctor"
	"github.com/hope61/tunl/internal/netsetup"
	"github.com/hope61/tunl/internal/systemd"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply the tunnel configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}
		if err := netsetup.Up(cfg); err != nil {
			return err
		}
		fmt.Println("Tunnel is up.")
		return nil
	},
}

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Tear down the tunnel",
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}
		if err := netsetup.Down(cfg); err != nil {
			return err
		}
		fmt.Println("Tunnel is down.")
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show tunnel status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}

		ifaceUp := netsetup.InterfaceExists(cfg.Interface)
		fmt.Printf("Role:      %s\n", cfg.Role)
		fmt.Printf("Interface: %s (up=%v)\n", cfg.Interface, ifaceUp)

		if ifaceUp {
			status, err := netsetup.GetPeerStatus(cfg.Interface)
			if err != nil {
				fmt.Printf("Peer:      error: %v\n", err)
			} else if status == nil {
				fmt.Println("Peer:      none configured")
			} else {
				handshake := "never"
				if !status.LastHandshake.IsZero() {
					handshake = fmt.Sprintf("%s ago", time.Since(status.LastHandshake).Round(time.Second))
				}
				fmt.Printf("Peer:      %s\n", status.PublicKey)
				if status.Endpoint != "" {
					fmt.Printf("Endpoint:  %s\n", status.Endpoint)
				}
				fmt.Printf("Handshake: %s\n", handshake)
				fmt.Printf("Transfer:  rx=%d tx=%d bytes\n", status.TransferRx, status.TransferTx)
			}
		}

		rulesPresent := netsetup.TableExists()
		fmt.Printf("Firewall:  inet tunl table present=%v\n", rulesPresent)

		if len(cfg.Forwards) > 0 {
			fmt.Println("Forwards:")
			for _, f := range cfg.Forwards {
				to := ""
				if f.ToPort != 0 {
					to = fmt.Sprintf(" -> %d", f.ToPort)
				}
				name := ""
				if f.Name != "" {
					name = fmt.Sprintf(" (%s)", f.Name)
				}
				snat := ""
				if f.SNAT {
					snat = " [snat]"
				}
				fmt.Printf("  %d/%s%s%s%s\n", f.Port, f.Proto, to, name, snat)
			}
		}
		return nil
	},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run diagnostic checks",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}

		checks := doctor.RunAll(cfg)
		hasIssues := false
		for _, c := range checks {
			icon := "✓"
			if c.Status == "warn" {
				icon = "⚠"
				hasIssues = true
			} else if c.Status == "fail" {
				icon = "✗"
				hasIssues = true
			}
			fmt.Printf("[%s] %s: %s\n", icon, c.Name, c.Detail)
			if c.Fix != "" {
				fmt.Printf("    Fix: %s\n", c.Fix)
			}
		}
		if hasIssues {
			os.Exit(1)
		}
		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove tunnel, firewall rules, systemd unit, and sysctl config",
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not load config: %v\n", err)
			fmt.Println("Cleaning up what we can...")
			netsetup.RemoveRules()
			systemd.Uninstall()
			netsetup.RemoveSysctlFile()
			return nil
		}

		netsetup.Uninstall(cfg)
		systemd.Uninstall()

		keepConfig, _ := cmd.Flags().GetBool("keep-config")
		if !keepConfig {
			if err := os.RemoveAll(config.DefaultDir); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not remove %s: %v\n", config.DefaultDir, err)
			}
		}

		if netsetup.IsIPForwardEnabled() {
			fmt.Println("Warning: ip_forward is still enabled. Other software (e.g. Docker) may rely on it.")
			fmt.Println("         The sysctl file has been removed; ip_forward will revert on reboot")
			fmt.Println("         unless another service enables it.")
		}

		fmt.Println("tunl has been uninstalled.")
		return nil
	},
}

func init() {
	uninstallCmd.Flags().Bool("keep-config", false, "Keep configuration files")
	rootCmd.AddCommand(upCmd, downCmd, statusCmd, doctorCmd, uninstallCmd)
}
