package netsetup

import (
	"fmt"

	"github.com/hope61/tunl/internal/config"
)

func Up(cfg *config.Config) error {
	if InterfaceExists(cfg.Interface) {
		if err := RemoveInterface(cfg.Interface); err != nil {
			return fmt.Errorf("removing existing interface: %w", err)
		}
	}

	if err := CreateInterface(cfg); err != nil {
		return err
	}

	if err := ConfigureWireGuard(cfg); err != nil {
		RemoveInterface(cfg.Interface)
		return err
	}

	if cfg.Role == config.RoleServer {
		if err := EnableIPForward(); err != nil {
			RemoveInterface(cfg.Interface)
			return err
		}
		if err := ApplyServerRules(cfg); err != nil {
			RemoveInterface(cfg.Interface)
			return err
		}
	} else {
		if err := ApplyAgentRules(cfg); err != nil {
			RemoveInterface(cfg.Interface)
			return err
		}
		if err := ApplyAgentConnmark(cfg); err != nil {
			RemoveInterface(cfg.Interface)
			RemoveRules()
			return err
		}
		if err := ApplyAgentRouting(cfg.Interface, cfg.TunnelAddr, cfg.PeerAddr); err != nil {
			RemoveInterface(cfg.Interface)
			RemoveRules()
			return err
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
