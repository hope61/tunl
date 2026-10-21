package systemd

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	unitName = "tunl.service"
	unitPath = "/etc/systemd/system/" + unitName
)

const unitTemplate = `[Unit]
Description=tunl WireGuard tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/tunl up
ExecStop=/usr/local/bin/tunl down

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/tunl
PrivateTmp=yes
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
`

func Install() error {
	if err := os.WriteFile(unitPath, []byte(unitTemplate), 0644); err != nil {
		return fmt.Errorf("writing systemd unit: %w", err)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if err := run("systemctl", "enable", unitName); err != nil {
		return fmt.Errorf("enabling unit: %w", err)
	}
	return nil
}

func Uninstall() error {
	run("systemctl", "stop", unitName)
	run("systemctl", "disable", unitName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing unit file: %w", err)
	}
	run("systemctl", "daemon-reload")
	return nil
}

func IsInstalled() bool {
	_, err := os.Stat(unitPath)
	return err == nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
