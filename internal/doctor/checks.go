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
	checks = append(checks, checkMSSClamp(cfg))
	checks = append(checks, checkSubnetCollision(cfg))

	if cfg.Role == config.RoleServer {
		checks = append(checks, checkPortConflicts(cfg)...)
		checks = append(checks, checkCloudflareProxy(cfg))
		checks = append(checks, checkUFWServer(cfg)...)
	}
	if cfg.Role == config.RoleAgent {
		checks = append(checks, checkRoutingRules())
		checks = append(checks, checkRPFilter(cfg))
		checks = append(checks, checkExposedPorts(cfg)...)
		checks = append(checks, checkUFWAgent(cfg))
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
		if cfg.Role == config.RoleServer {
			c.Fix = fmt.Sprintf("agent hasn't connected — verify it joined and UDP port %d is open in your cloud provider's firewall", cfg.ListenPort)
		} else {
			c.Fix = fmt.Sprintf("can't reach server at %s — check that the port is open in the VPS cloud firewall and OS firewall (ufw, iptables)", cfg.Endpoint)
		}
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

func checkMSSClamp(cfg *config.Config) Check {
	c := Check{Name: "TCP MSS clamping"}
	chains := []string{netsetup.ChainMSSPrerouting, netsetup.ChainMSSPostrouting}
	if cfg.Role == config.RoleServer {
		chains = []string{netsetup.ChainMSSForward}
	}
	for _, name := range chains {
		if !netsetup.ChainExists(name) {
			c.Status = "fail"
			c.Detail = fmt.Sprintf("chain %s missing; large TCP packets may stall over the tunnel", name)
			c.Fix = "tunl up"
			return c
		}
	}
	c.Status = "ok"
	c.Detail = fmt.Sprintf("MSS clamped to %d on %s", cfg.MTU-40, cfg.Interface)
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

func checkRPFilter(cfg *config.Config) Check {
	c := Check{Name: "rp_filter"}
	allVal := readSysctl("/proc/sys/net/ipv4/conf/all/rp_filter")
	ifVal := readSysctl(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", cfg.Interface))

	if allVal == "1" || ifVal == "1" {
		c.Status = "fail"
		c.Detail = "strict reverse-path filtering will drop tunnel traffic with public source IPs"
		c.Fix = "tunl up (auto-fixes this), or: sysctl -w net.ipv4.conf.all.rp_filter=2"
	} else {
		c.Status = "ok"
		c.Detail = "loose mode"
	}
	return c
}

func readSysctl(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func checkUFWServer(cfg *config.Config) []Check {
	var checks []Check
	if !netsetup.IsUFWActive() {
		return checks
	}

	c := Check{Name: "ufw WireGuard port"}
	if netsetup.UFWHasRule(fmt.Sprintf("%d/udp", cfg.ListenPort)) {
		c.Status = "ok"
		c.Detail = fmt.Sprintf("UDP %d is allowed", cfg.ListenPort)
	} else {
		c.Status = "fail"
		c.Detail = fmt.Sprintf("UDP %d is not allowed in ufw — WireGuard packets will be dropped", cfg.ListenPort)
		c.Fix = fmt.Sprintf("tunl up (auto-fixes this), or: ufw allow %d/udp", cfg.ListenPort)
	}
	checks = append(checks, c)

	c2 := Check{Name: "ufw tunnel forwarding"}
	if netsetup.UFWHasRule(fmt.Sprintf("on %s", cfg.Interface)) {
		c2.Status = "ok"
		c2.Detail = "tunnel forwarding allowed"
	} else {
		c2.Status = "fail"
		c2.Detail = "forwarded traffic through the tunnel may be blocked by ufw"
		c2.Fix = fmt.Sprintf("tunl up (auto-fixes this), or: ufw route allow in on %s", cfg.Interface)
	}
	checks = append(checks, c2)

	return checks
}

func checkUFWAgent(cfg *config.Config) Check {
	c := Check{Name: "ufw"}
	if !netsetup.IsUFWActive() {
		c.Status = "ok"
		c.Detail = "inactive"
	} else if netsetup.UFWHasRule(fmt.Sprintf("on %s", cfg.Interface)) {
		c.Status = "ok"
		c.Detail = "tunnel forwarding allowed"
	} else {
		c.Status = "warn"
		c.Detail = "ufw is active — forwarded traffic (e.g. Docker containers) may be blocked"
		c.Fix = fmt.Sprintf("tunl up (auto-fixes this), or: ufw route allow in on %s", cfg.Interface)
	}
	return c
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
