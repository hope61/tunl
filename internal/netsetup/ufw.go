package netsetup

import (
	"fmt"
	"os/exec"
	"strings"
)

func IsUFWActive() bool {
	out, err := exec.Command("ufw", "status").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: active")
}

func UFWAllowPort(port int, proto string) error {
	out, err := exec.Command("ufw", "allow", fmt.Sprintf("%d/%s", port, proto)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw allow %d/%s: %s", port, proto, strings.TrimSpace(string(out)))
	}
	return nil
}

func UFWAllowTunnelForwarding(iface string) error {
	out, err := exec.Command("ufw", "route", "allow", "in", "on", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw route allow in on %s: %s", iface, strings.TrimSpace(string(out)))
	}
	return nil
}

func UFWHasRule(search string) bool {
	out, err := exec.Command("ufw", "status").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), search)
}
