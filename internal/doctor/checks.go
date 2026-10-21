package doctor

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hope61/tunl/internal/config"
	"github.com/hope61/tunl/internal/netsetup"
)

type Check struct {
	Name   string
	Status string // "ok", "warn", "fail"
	Detail string
	Fix    string
}

func RunAll(cfg *config.Config) []Check {
	var checks []Check

	checks = append(checks, checkInterface(cfg))
	checks = append(checks, checkIPForward(cfg))
	checks = append(checks, checkHandshake(cfg))
	checks = append(checks, checkNftables())
	checks = append(checks, checkSubnetCollision(cfg))

	if cfg.Role == config.RoleServer {
		checks = append(checks, checkPortConflicts(cfg)...)
		checks = append(checks, checkCloudflareProxy(cfg))
	}
	if cfg.Role == config.RoleAgent {
		checks = append(checks, checkRoutingRules())
		checks = append(checks, checkExposedPorts(cfg)...)
	}

	return checks
}

func checkInterface(cfg *config.Config) Check {
	c := Check{Name: "WireGuard interface"}
	if netsetup.InterfaceExists(cfg.Interface) {
		c.Status = "ok"
		c.Detail = fmt.Sprintf("%s is up", cfg.Interface)
	} else {
		c.Status = "fail"
		c.Detail = fmt.Sprintf("%s is not present", cfg.Interface)
		c.Fix = "tunl up"
	}
	return c
}

func checkIPForward(cfg *config.Config) Check {
	c := Check{Name: "IP forwarding"}
	if cfg.Role != config.RoleServer {
		c.Status = "ok"
		c.Detail = "not required on agent"
		return c
	}
	if netsetup.IsIPForwardEnabled() {
		c.Status = "ok"
		c.Detail = "enabled"
	} else {
		c.Status = "fail"
		c.Detail = "ip_forward is disabled"
		c.Fix = "echo 1 > /proc/sys/net/ipv4/ip_forward"
	}
	return c
}

func checkHandshake(cfg *config.Config) Check {
	c := Check{Name: "WireGuard handshake"}
	status, err := netsetup.GetPeerStatus(cfg.Interface)
	if err != nil {
		c.Status = "fail"
		c.Detail = err.Error()
		return c
	}
	if status == nil {
		c.Status = "warn"
		c.Detail = "no peer configured"
		return c
	}
	if status.LastHandshake.IsZero() {
		c.Status = "fail"
		c.Detail = "no handshake yet"
		c.Fix = "check endpoint reachability, firewall, and peer key authorization"
		return c
	}
	age := status.HandshakeAge
	if age > 5*time.Minute {
		c.Status = "warn"
		c.Detail = fmt.Sprintf("last handshake %s ago (stale)", age.Round(time.Second))
		c.Fix = "check connectivity and peer configuration"
	} else {
		c.Status = "ok"
		c.Detail = fmt.Sprintf("last handshake %s ago", age.Round(time.Second))
	}
	return c
}

func checkNftables() Check {
	c := Check{Name: "nftables rules"}
	if netsetup.TableExists() {
		c.Status = "ok"
		c.Detail = "inet tunl table present"
	} else {
		c.Status = "fail"
		c.Detail = "inet tunl table missing"
		c.Fix = "tunl up"
	}
	return c
}

func checkPortConflicts(cfg *config.Config) []Check {
	var checks []Check
	for _, fwd := range cfg.Forwards {
		c := Check{Name: fmt.Sprintf("port %d/%s", fwd.Port, fwd.Proto)}
		if config.CheckPortListening(fwd.Port, fwd.Proto) {
			c.Status = "warn"
			c.Detail = fmt.Sprintf("port %d/%s is already in use on the VPS", fwd.Port, fwd.Proto)
			c.Fix = fmt.Sprintf("check what is using port %d/%s: ss -tlnp | grep %d", fwd.Port, fwd.Proto, fwd.Port)
		} else {
			c.Status = "ok"
			c.Detail = "available"
		}
		checks = append(checks, c)
	}
	return checks
}

func checkSubnetCollision(cfg *config.Config) Check {
	c := Check{Name: "subnet collision"}
	ifaces, err := net.Interfaces()
	if err != nil {
		c.Status = "warn"
		c.Detail = "could not list interfaces"
		return c
	}
	_, tunnelNet, err := net.ParseCIDR(cfg.Subnet)
	if err != nil {
		c.Status = "fail"
		c.Detail = "invalid subnet in config"
		return c
	}
	for _, iface := range ifaces {
		if iface.Name == cfg.Interface {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if tunnelNet.Contains(ipNet.IP) || ipNet.Contains(tunnelNet.IP) {
				c.Status = "warn"
				c.Detail = fmt.Sprintf("subnet %s overlaps with %s on %s", cfg.Subnet, addr.String(), iface.Name)
				c.Fix = fmt.Sprintf("change tunnel subnet (currently %s)", cfg.Subnet)
				return c
			}
		}
	}
	c.Status = "ok"
	c.Detail = "no collision"
	return c
}

func checkRoutingRules() Check {
	c := Check{Name: "policy routing"}
	if netsetup.HasIPRule(uint32(netsetup.FWMark), 100) {
		c.Status = "ok"
		c.Detail = "fwmark ip rule present"
	} else {
		c.Status = "fail"
		c.Detail = "fwmark ip rule missing"
		c.Fix = "tunl up"
	}
	return c
}

func checkExposedPorts(cfg *config.Config) []Check {
	var checks []Check
	for _, fwd := range cfg.Forwards {
		port := fwd.Port
		if fwd.ToPort != 0 {
			port = fwd.ToPort
		}
		c := Check{Name: fmt.Sprintf("exposed %d/%s", port, fwd.Proto)}
		if !isPortListeningLocal(port, fwd.Proto) {
			c.Status = "warn"
			c.Detail = fmt.Sprintf("port %d/%s is not listening on this machine", port, fwd.Proto)
			c.Fix = fmt.Sprintf("start the service listening on port %d/%s", port, fwd.Proto)
		} else {
			c.Status = "ok"
			c.Detail = "service is listening"
		}
		checks = append(checks, c)
	}
	return checks
}

func isPortListeningLocal(port uint16, proto string) bool {
	return config.CheckPortListening(port, proto)
}

func checkCloudflareProxy(cfg *config.Config) Check {
	c := Check{Name: "Cloudflare proxy check"}
	host, _, err := net.SplitHostPort(cfg.Endpoint)
	if err != nil {
		c.Status = "ok"
		c.Detail = "could not parse endpoint"
		return c
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		c.Status = "ok"
		c.Detail = "DNS lookup failed (IP endpoint?)"
		return c
	}
	for _, ip := range ips {
		if isCloudflareIP(ip) {
			c.Status = "warn"
			c.Detail = fmt.Sprintf("%s resolves to Cloudflare IP %s — WireGuard UDP won't work through the proxy", host, ip)
			c.Fix = fmt.Sprintf("set the DNS record for %s to 'DNS only' (grey cloud) in Cloudflare", host)
			return c
		}
	}
	c.Status = "ok"
	c.Detail = "endpoint is not proxied through Cloudflare"
	return c
}

var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

func isCloudflareIP(ip net.IP) bool {
	for _, cidr := range cloudflareRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	data, err := os.ReadFile("/etc/tunl/cloudflare-ips.txt")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
