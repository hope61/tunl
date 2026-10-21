package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hope61/tunl/internal/config"
	"github.com/hope61/tunl/internal/netsetup"
)

var addCmd = &cobra.Command{
	Use:   "add <port/proto>",
	Short: "Add a port forward (server only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		port, proto, err := config.ParsePortProto(args[0])
		if err != nil {
			return err
		}

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}
		if cfg.Role != config.RoleServer {
			return fmt.Errorf("this machine is configured as %s, not server", cfg.Role)
		}

		if _, exists := cfg.FindForward(port, proto); exists {
			return fmt.Errorf("forward %d/%s already exists", port, proto)
		}

		force, _ := cmd.Flags().GetBool("force")
		if err := config.CheckPortConflict(port, proto, cfg.ListenPort, force); err != nil {
			return err
		}
		if !force && config.CheckPortListening(port, proto) {
			return fmt.Errorf("port %d/%s is already in use on this machine; use --force to override", port, proto)
		}

		toPort, _ := cmd.Flags().GetUint16("to")
		name, _ := cmd.Flags().GetString("name")
		snat, _ := cmd.Flags().GetBool("snat")

		if err := config.ValidateName(name); err != nil {
			return err
		}

		fwd := config.Forward{
			Port:   port,
			Proto:  proto,
			ToPort: toPort,
			Name:   name,
			SNAT:   snat,
		}
		cfg.Forwards = append(cfg.Forwards, fwd)

		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
		if err := config.Save(config.DefaultPath(), cfg); err != nil {
			return err
		}
		if err := netsetup.Up(cfg); err != nil {
			return fmt.Errorf("applying rules: %w", err)
		}

		fmt.Printf("Added forward %d/%s", port, proto)
		if toPort != 0 {
			fmt.Printf(" -> %d", toPort)
		}
		fmt.Println()
		return nil
	},
}

var removeCmd = &cobra.Command{
	Use:   "remove <port/proto>",
	Short: "Remove a port forward (server only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		port, proto, err := config.ParsePortProto(args[0])
		if err != nil {
			return err
		}

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}
		if cfg.Role != config.RoleServer {
			return fmt.Errorf("this machine is configured as %s, not server", cfg.Role)
		}

		idx, exists := cfg.FindForward(port, proto)
		if !exists {
			return fmt.Errorf("forward %d/%s not found", port, proto)
		}

		cfg.Forwards = append(cfg.Forwards[:idx], cfg.Forwards[idx+1:]...)

		if err := config.Save(config.DefaultPath(), cfg); err != nil {
			return err
		}
		if err := netsetup.Up(cfg); err != nil {
			return fmt.Errorf("applying rules: %w", err)
		}

		fmt.Printf("Removed forward %d/%s\n", port, proto)
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all port forwards",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}

		if len(cfg.Forwards) == 0 {
			fmt.Println("No forwards configured.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PORT\tPROTO\tTO\tNAME\tSNAT")
		for _, f := range cfg.Forwards {
			to := "-"
			if f.ToPort != 0 {
				to = fmt.Sprintf("%d", f.ToPort)
			}
			name := f.Name
			if name == "" {
				name = "-"
			}
			snat := "no"
			if f.SNAT {
				snat = "yes"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", f.Port, f.Proto, to, name, snat)
		}
		w.Flush()
		return nil
	},
}

var exposeCmd = &cobra.Command{
	Use:   "expose <port/proto>",
	Short: "Allow a port through the tunnel firewall (agent only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		port, proto, err := config.ParsePortProto(args[0])
		if err != nil {
			return err
		}

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}
		if cfg.Role != config.RoleAgent {
			return fmt.Errorf("this machine is configured as %s, not agent", cfg.Role)
		}

		if _, exists := cfg.FindForward(port, proto); exists {
			return fmt.Errorf("port %d/%s is already exposed", port, proto)
		}

		cfg.Forwards = append(cfg.Forwards, config.Forward{
			Port:  port,
			Proto: proto,
		})

		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
		if err := config.Save(config.DefaultPath(), cfg); err != nil {
			return err
		}
		if err := netsetup.Up(cfg); err != nil {
			return fmt.Errorf("applying rules: %w", err)
		}

		fmt.Printf("Exposed port %d/%s through tunnel\n", port, proto)
		return nil
	},
}

var unexposeCmd = &cobra.Command{
	Use:   "unexpose <port/proto>",
	Short: "Block a port through the tunnel firewall (agent only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		lock, err := config.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Release()

		port, proto, err := config.ParsePortProto(args[0])
		if err != nil {
			return err
		}

		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return err
		}
		if cfg.Role != config.RoleAgent {
			return fmt.Errorf("this machine is configured as %s, not agent", cfg.Role)
		}

		idx, exists := cfg.FindForward(port, proto)
		if !exists {
			return fmt.Errorf("port %d/%s is not exposed", port, proto)
		}

		cfg.Forwards = append(cfg.Forwards[:idx], cfg.Forwards[idx+1:]...)

		if err := config.Save(config.DefaultPath(), cfg); err != nil {
			return err
		}
		if err := netsetup.Up(cfg); err != nil {
			return fmt.Errorf("applying rules: %w", err)
		}

		fmt.Printf("Unexposed port %d/%s\n", port, proto)
		return nil
	},
}

func init() {
	addCmd.Flags().Uint16("to", 0, "Destination port on the agent (defaults to same port)")
	addCmd.Flags().String("name", "", "Label for this forward")
	addCmd.Flags().Bool("snat", false, "Masquerade traffic (agent sees tunnel IP, not real client IP)")
	addCmd.Flags().Bool("force", false, "Override safety checks")

	rootCmd.AddCommand(addCmd, removeCmd, listCmd, exposeCmd, unexposeCmd)
}
