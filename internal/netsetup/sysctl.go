package netsetup

import (
	"fmt"
	"os"
	"strings"
)

const (
	sysctlFile     = "/etc/sysctl.d/99-tunl.conf"
	ipForwardProc  = "/proc/sys/net/ipv4/ip_forward"
	ipForwardValue = "net.ipv4.ip_forward = 1\n"
	rpFilterAll    = "/proc/sys/net/ipv4/conf/all/rp_filter"
)

func EnableIPForward() error {
	current, err := os.ReadFile(ipForwardProc)
	if err != nil {
		return fmt.Errorf("reading ip_forward: %w", err)
	}
	if strings.TrimSpace(string(current)) == "1" {
		return ensureSysctlFile()
	}

	if err := os.WriteFile(ipForwardProc, []byte("1"), 0644); err != nil {
		if strings.TrimSpace(string(current)) == "1" {
			return ensureSysctlFile()
		}
		return fmt.Errorf("enabling ip_forward (is /proc/sys read-only?): %w", err)
	}
	return ensureSysctlFile()
}

func ensureSysctlFile() error {
	if err := os.WriteFile(sysctlFile, []byte(ipForwardValue), 0644); err != nil {
		return nil
	}
	return nil
}

func RemoveSysctlFile() error {
	if err := os.Remove(sysctlFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing sysctl file: %w", err)
	}
	return nil
}

func SetLooseRPFilter(ifaceName string) error {
	paths := []string{
		rpFilterAll,
		fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifaceName),
	}
	for _, p := range paths {
		current, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(current)) == "0" || strings.TrimSpace(string(current)) == "2" {
			continue
		}
		if err := os.WriteFile(p, []byte("2"), 0644); err != nil {
			return fmt.Errorf("setting rp_filter on %s: %w", p, err)
		}
	}
	return nil
}

func IsIPForwardEnabled() bool {
	data, err := os.ReadFile(ipForwardProc)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}
