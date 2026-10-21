package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePortProto(t *testing.T) {
	tests := []struct {
		input     string
		wantPort  uint16
		wantProto string
		wantErr   bool
	}{
		{"25565/tcp", 25565, "tcp", false},
		{"53/udp", 53, "udp", false},
		{"1/tcp", 1, "tcp", false},
		{"65535/udp", 65535, "udp", false},
		{"0/tcp", 0, "", true},
		{"65536/tcp", 0, "", true},
		{"-1/tcp", 0, "", true},
		{"abc/tcp", 0, "", true},
		{"25565/icmp", 0, "", true},
		{"25565", 0, "", true},
		{"", 0, "", true},
		{"25565/TCP", 25565, "tcp", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			port, proto, err := ParsePortProto(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePortProto(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if port != tt.wantPort {
				t.Errorf("ParsePortProto(%q) port = %d, want %d", tt.input, port, tt.wantPort)
			}
			if proto != tt.wantProto {
				t.Errorf("ParsePortProto(%q) proto = %q, want %q", tt.input, proto, tt.wantProto)
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"", false},
		{"minecraft", false},
		{"my-server_1", false},
		{"a", false},
		{"12345678901234567890123456789012", false},
		{"123456789012345678901234567890123", true},
		{"has spaces", true},
		{"has.dots", true},
		{"has/slash", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"vps.example.com:51821", "vps.example.com:51821", false},
		{"1.2.3.4:51821", "1.2.3.4:51821", false},
		{"host:1", "host:1", false},
		{"host:65535", "host:65535", false},
		{"host:0", "", true},
		{"host:65536", "", true},
		{"host", "", true},
		{":51821", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ValidateEndpoint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEndpoint(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateEndpoint(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateWGKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", false},
		{"bad base64", "not-base64!", true},
		{"wrong length", "AAAA", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWGKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWGKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	validKey := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

	base := Config{
		Role:       RoleServer,
		Interface:  "tunl0",
		MTU:        1420,
		PrivateKey: validKey,
		PublicKey:  validKey,
		Endpoint:   "vps.example.com:51821",
		ListenPort: 51821,
		TunnelAddr: "10.77.0.1",
		PeerAddr:   "10.77.0.2",
		Subnet:     "10.77.0.0/24",
	}

	t.Run("valid server config", func(t *testing.T) {
		cfg := base
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid role", func(t *testing.T) {
		cfg := base
		cfg.Role = "invalid"
		if err := cfg.Validate(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("invalid MTU", func(t *testing.T) {
		cfg := base
		cfg.MTU = 100
		if err := cfg.Validate(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("duplicate forwards", func(t *testing.T) {
		cfg := base
		cfg.Forwards = []Forward{
			{Port: 25565, Proto: "tcp"},
			{Port: 25565, Proto: "tcp"},
		}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for duplicate forwards")
		}
	})

	t.Run("same port different proto is ok", func(t *testing.T) {
		cfg := base
		cfg.Forwards = []Forward{
			{Port: 25565, Proto: "tcp"},
			{Port: 25565, Proto: "udp"},
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "config.json")
	validKey := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

	cfg := &Config{
		Role:       RoleServer,
		Interface:  "tunl0",
		MTU:        1420,
		PrivateKey: validKey,
		PublicKey:  validKey,
		Endpoint:   "vps.example.com:51821",
		ListenPort: 51821,
		TunnelAddr: "10.77.0.1",
		PeerAddr:   "10.77.0.2",
		Subnet:     "10.77.0.0/24",
		Forwards: []Forward{
			{Port: 25565, Proto: "tcp", Name: "minecraft"},
		},
	}

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Role != cfg.Role {
		t.Errorf("Role = %v, want %v", loaded.Role, cfg.Role)
	}
	if len(loaded.Forwards) != 1 {
		t.Fatalf("Forwards len = %d, want 1", len(loaded.Forwards))
	}
	if loaded.Forwards[0].Name != "minecraft" {
		t.Errorf("Forward name = %q, want %q", loaded.Forwards[0].Name, "minecraft")
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")

	data := map[string]interface{}{
		"role":        "server",
		"interface":   "tunl0",
		"mtu":         1420,
		"unknown_key": "should fail",
	}
	raw, _ := json.Marshal(data)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for unknown field, got nil")
	}
}

func TestFindForward(t *testing.T) {
	cfg := &Config{
		Forwards: []Forward{
			{Port: 25565, Proto: "tcp"},
			{Port: 53, Proto: "udp"},
		},
	}

	idx, found := cfg.FindForward(25565, "tcp")
	if !found || idx != 0 {
		t.Errorf("FindForward(25565/tcp) = %d, %v; want 0, true", idx, found)
	}

	idx, found = cfg.FindForward(53, "udp")
	if !found || idx != 1 {
		t.Errorf("FindForward(53/udp) = %d, %v; want 1, true", idx, found)
	}

	_, found = cfg.FindForward(80, "tcp")
	if found {
		t.Error("FindForward(80/tcp) should not be found")
	}
}
