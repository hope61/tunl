package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	encoded, err := Encode(
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		"vps.example.com:51821",
		"10.77.0.1",
		"10.77.0.2",
		"10.77.0.0/24",
		"tunl0",
		1420,
		51821,
	)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tok, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if tok.Version != Version {
		t.Errorf("Version = %d, want %d", tok.Version, Version)
	}
	if tok.ServerPub != "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=" {
		t.Errorf("ServerPub = %q", tok.ServerPub)
	}
	if tok.Endpoint != "vps.example.com:51821" {
		t.Errorf("Endpoint = %q", tok.Endpoint)
	}
	if tok.ServerAddr != "10.77.0.1" {
		t.Errorf("ServerAddr = %q", tok.ServerAddr)
	}
	if tok.AgentAddr != "10.77.0.2" {
		t.Errorf("AgentAddr = %q", tok.AgentAddr)
	}
	if tok.Subnet != "10.77.0.0/24" {
		t.Errorf("Subnet = %q", tok.Subnet)
	}
	if tok.MTU != 1420 {
		t.Errorf("MTU = %d", tok.MTU)
	}
}

func TestDecodeInvalidBase64(t *testing.T) {
	_, err := Decode("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecodeWrongVersion(t *testing.T) {
	encoded, _ := Encode(
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		"host:1234", "10.0.0.1", "10.0.0.2", "10.0.0.0/24", "wg0", 1420, 51821,
	)
	raw, _ := base64.URLEncoding.DecodeString(encoded)
	tampered := strings.Replace(string(raw), `"v":1`, `"v":99`, 1)
	reencoded := base64.URLEncoding.EncodeToString([]byte(tampered))

	_, err := Decode(reencoded)
	if err == nil {
		t.Error("expected error for wrong version")
	}
	if !strings.Contains(err.Error(), "unsupported token version") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecodeCorruptedChecksum(t *testing.T) {
	encoded, _ := Encode(
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		"host:1234", "10.0.0.1", "10.0.0.2", "10.0.0.0/24", "wg0", 1420, 51821,
	)
	raw, _ := base64.URLEncoding.DecodeString(encoded)
	tampered := strings.Replace(string(raw), "host:1234", "host:9999", 1)
	reencoded := base64.URLEncoding.EncodeToString([]byte(tampered))

	_, err := Decode(reencoded)
	if err == nil {
		t.Error("expected error for corrupted token")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecodeMissingFields(t *testing.T) {
	raw := `{"v":1,"spk":"","ep":"","sa":"","aa":"","sn":"","iface":"","mtu":0,"lp":0,"cs":""}`
	tok := base64.URLEncoding.EncodeToString([]byte(raw))
	_, err := Decode(tok)
	if err == nil {
		t.Error("expected error for missing fields")
	}
}
