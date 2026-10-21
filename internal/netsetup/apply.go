package netsetup

import (
	"fmt"

	"github.com/hope61/tunl/internal/config"
)

func Up(cfg *config.Config) error {
	needsWGUpdate := !InterfaceExists(cfg.Interface)

	if needsWGUpdate {
		if err := CreateInterface(cfg); err != nil {
			return err
		}
		if err := ConfigureWireGuard(cfg); err != nil {
			RemoveInterface(cfg.Interface)
			return err
		}
	} else {
		if err := wgNeedsUpdate(cfg); err == nil {
			if err := ConfigureWireGuard(cfg); err != nil {
				return err
			}
		}
	}

	cleanup := func() {
		if needsWGUpdate {
			RemoveInterface(cfg.Interface)
		}
	}

	if cfg.Role == config.RoleServer {
		if err := EnableIPForward(); err != nil {
			cleanup()
			return err
		}
		if err := ApplyServerRules(cfg); err != nil {
			cleanup()
			return err
		}
	} else {
		if err := ApplyAgentRules(cfg); err != nil {
			cleanup()
			return err
		}
		if err := ApplyAgentConnmark(cfg); err != nil {
			cleanup()
			RemoveRules()
			return err
		}
		if err := SetLooseRPFilter(cfg.Interface); err != nil {
			cleanup()
			RemoveRules()
			return err
		}
		if err := ApplyAgentRouting(cfg.Interface, cfg.TunnelAddr, cfg.PeerAddr); err != nil {
			cleanup()
			RemoveRules()
			return err
		}
	}

	configureUFW(cfg)

	return nil
}

func configureUFW(cfg *config.Config) {
	if !IsUFWActive() {
		return
	}
	if cfg.Role == config.RoleServer {
		UFWAllowPort(cfg.ListenPort, "udp")
		UFWAllowTunnelForwarding(cfg.Interface)
	} else {
		UFWAllowTunnelForwarding(cfg.Interface)
	}
}

// wgNeedsUpdate returns nil if WG config needs updating (peer mismatch).
func wgNeedsUpdate(cfg *config.Config) error {
	status, err := GetPeerStatus(cfg.Interface)
	if err != nil {
		return nil // can't determine, update to be safe
	}

	if cfg.Role == config.RoleServer {
		if cfg.AllowedAgentKey == "" && status == nil {
			return fmt.Errorf("no update needed")
		}
		if cfg.AllowedAgentKey != "" && status != nil && status.PublicKey == cfg.AllowedAgentKey {
			return fmt.Errorf("no update needed")
		}
	} else {
		if status != nil && status.PublicKey == cfg.PeerPubKey {
			return fmt.Errorf("no update needed")
		}
	}
	return nil
}

func Down(cfg *config.Config) error {
	var errs []error
	if err := RemoveRules(); err != nil {
		errs = append(errs, err)
	}
	if cfg.Role == config.RoleAgent {
		if err := RemoveAgentRouting(cfg.Interface, cfg.PeerAddr); err != nil {
			errs = append(errs, err)
		}
	}
	if err := RemoveInterface(cfg.Interface); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors during teardown: %v", errs)
	}
	return nil
}

func Uninstall(cfg *config.Config) error {
	Down(cfg)
	RemoveSysctlFile()
	return nil
}
