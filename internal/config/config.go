package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	DefaultDir       = "/etc/tunl"
	DefaultFile      = "config.json"
	DefaultInterface = "tunl0"
	DefaultPort      = 51821
	DefaultSubnet    = "10.77.0.0/24"
	DefaultMTU       = 1420
	DefaultServerIP  = "10.77.0.1"
	DefaultAgentIP   = "10.77.0.2"

	DirPerms  os.FileMode = 0700
	FilePerms os.FileMode = 0600
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

type Role string

const (
	RoleServer Role = "server"
	RoleAgent  Role = "agent"
)

type Forward struct {
	Port   uint16 `json:"port"`
	Proto  string `json:"proto"`
	ToPort uint16 `json:"to_port,omitempty"`
	Name   string `json:"name,omitempty"`
	SNAT   bool   `json:"snat,omitempty"`
}

func (f Forward) Key() string {
	return fmt.Sprintf("%d/%s", f.Port, f.Proto)
}

type Config struct {
	Role      Role   `json:"role"`
	Interface string `json:"interface"`
	MTU       int    `json:"mtu"`

	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`

	Endpoint   string `json:"endpoint,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	PeerPubKey string `json:"peer_public_key,omitempty"`
	TunnelAddr string `json:"tunnel_addr"`
	PeerAddr   string `json:"peer_addr"`
	Subnet     string `json:"subnet"`

	Forwards []Forward `json:"forwards,omitempty"`

	AllowedAgentKey string `json:"allowed_agent_key,omitempty"`
}

func DefaultPath() string {
	return filepath.Join(DefaultDir, DefaultFile)
}

func Load(path string) (*Config, error) {
	if err := checkPerms(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &c, nil
}

func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), DirPerms); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, FilePerms)
	if err != nil {
		return fmt.Errorf("creating temp config: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writing config: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("syncing config: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("closing config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming config: %w", err)
	}
	return nil
}

func checkPerms(path string) error {
	dir := filepath.Dir(path)
	di, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat config dir: %w", err)
	}
	if di.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("config dir %s has permissions %o, want 0700", dir, di.Mode().Perm())
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config: %w", err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("config file %s has permissions %o, want 0600", path, fi.Mode().Perm())
	}
	return nil
}

type LockFile struct {
	f *os.File
}

func AcquireLock() (*LockFile, error) {
	lockPath := filepath.Join(DefaultDir, ".lock")
	if err := os.MkdirAll(DefaultDir, DirPerms); err != nil {
		return nil, fmt.Errorf("creating lock dir: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, FilePerms)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another tunl command is running (could not acquire lock)")
	}
	return &LockFile{f: f}, nil
}

func (l *LockFile) Release() {
	if l.f != nil {
		syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
		l.f.Close()
	}
}

func ParsePortProto(s string) (uint16, string, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid format %q, expected port/proto (e.g. 25565/tcp)", s)
	}
	port, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("port must be 1-65535, got %q", parts[0])
	}
	proto := strings.ToLower(parts[1])
	if proto != "tcp" && proto != "udp" {
		return 0, "", fmt.Errorf("protocol must be tcp or udp, got %q", parts[1])
	}
	return uint16(port), proto, nil
}

func ValidateName(name string) error {
	if name == "" {
		return nil
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name must be 1-32 chars of [a-zA-Z0-9_-], got %q", name)
	}
	return nil
}

func ValidateEndpoint(ep string) (string, error) {
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("endpoint must be host:port, got %q: %w", ep, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("endpoint port must be 1-65535, got %q", portStr)
	}
	if host == "" {
		return "", fmt.Errorf("endpoint host is empty")
	}
	return fmt.Sprintf("%s:%d", host, port), nil
}

func ValidateWGKey(key string) error {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid base64 WireGuard key: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("WireGuard key must be 32 bytes, got %d", len(b))
	}
	return nil
}

func (c *Config) FindForward(port uint16, proto string) (int, bool) {
	key := fmt.Sprintf("%d/%s", port, proto)
	for i, f := range c.Forwards {
		if f.Key() == key {
			return i, true
		}
	}
	return -1, false
}

func (c *Config) Validate() error {
	if c.Role != RoleServer && c.Role != RoleAgent {
		return fmt.Errorf("invalid role %q", c.Role)
	}
	if c.Interface == "" {
		return errors.New("interface name is required")
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return fmt.Errorf("MTU must be 1280-65535, got %d", c.MTU)
	}
	if err := ValidateWGKey(c.PublicKey); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	if c.TunnelAddr == "" {
		return errors.New("tunnel address is required")
	}
	if ip := net.ParseIP(c.TunnelAddr); ip == nil {
		return fmt.Errorf("invalid tunnel address %q", c.TunnelAddr)
	}
	if c.PeerAddr == "" {
		return errors.New("peer address is required")
	}
	if ip := net.ParseIP(c.PeerAddr); ip == nil {
		return fmt.Errorf("invalid peer address %q", c.PeerAddr)
	}
	_, _, err := net.ParseCIDR(c.Subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet %q: %w", c.Subnet, err)
	}
	if c.Role == RoleServer {
		if c.Endpoint == "" {
			return errors.New("server requires endpoint")
		}
		if _, err := ValidateEndpoint(c.Endpoint); err != nil {
			return err
		}
		if c.ListenPort < 1 || c.ListenPort > 65535 {
			return fmt.Errorf("listen port must be 1-65535, got %d", c.ListenPort)
		}
	}
	seen := make(map[string]bool)
	for _, f := range c.Forwards {
		if f.Port < 1 || f.Port > 65535 {
			return fmt.Errorf("forward port must be 1-65535, got %d", f.Port)
		}
		if f.Proto != "tcp" && f.Proto != "udp" {
			return fmt.Errorf("forward proto must be tcp or udp, got %q", f.Proto)
		}
		if f.ToPort != 0 && (f.ToPort < 1 || f.ToPort > 65535) {
			return fmt.Errorf("forward to_port must be 1-65535, got %d", f.ToPort)
		}
		if err := ValidateName(f.Name); err != nil {
			return fmt.Errorf("forward name: %w", err)
		}
		key := f.Key()
		if seen[key] {
			return fmt.Errorf("duplicate forward %s", key)
		}
		seen[key] = true
	}
	return nil
}

func DetectSSHPort() int {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return 22
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Port ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p <= 65535 {
					return p
				}
			}
		}
	}
	return 22
}

func CheckPortConflict(port uint16, proto string, wgPort int, force bool) error {
	if int(port) == wgPort {
		if !force {
			return fmt.Errorf("port %d is the WireGuard listen port; use --force to override", port)
		}
	}
	sshPort := DetectSSHPort()
	if int(port) == sshPort && proto == "tcp" {
		if !force {
			return fmt.Errorf("port %d is the SSH port; use --force to override", port)
		}
	}
	return nil
}

func CheckPortListening(port uint16, proto string) bool {
	addr := fmt.Sprintf(":%d", port)
	if proto == "tcp" {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			return true
		}
		ln.Close()
		return false
	}
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}
