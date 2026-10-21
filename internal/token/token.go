package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const Version = 1

type Token struct {
	Version    int    `json:"v"`
	ServerPub  string `json:"spk"`
	Endpoint   string `json:"ep"`
	ServerAddr string `json:"sa"`
	AgentAddr  string `json:"aa"`
	Subnet     string `json:"sn"`
	Interface  string `json:"iface"`
	MTU        int    `json:"mtu"`
	ListenPort int    `json:"lp"`
	Checksum   string `json:"cs"`
}

func Encode(serverPub, endpoint, serverAddr, agentAddr, subnet, iface string, mtu, listenPort int) (string, error) {
	t := Token{
		Version:    Version,
		ServerPub:  serverPub,
		Endpoint:   endpoint,
		ServerAddr: serverAddr,
		AgentAddr:  agentAddr,
		Subnet:     subnet,
		Interface:  iface,
		MTU:        mtu,
		ListenPort: listenPort,
	}
	t.Checksum = checksum(t)
	data, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("encoding token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

func Decode(encoded string) (*Token, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding: %w", err)
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("invalid token format: %w", err)
	}
	if t.Version != Version {
		return nil, fmt.Errorf("unsupported token version %d (expected %d)", t.Version, Version)
	}
	expected := checksum(t)
	if t.Checksum != expected {
		return nil, fmt.Errorf("token checksum mismatch (corrupted or tampered)")
	}
	if t.ServerPub == "" || t.Endpoint == "" || t.ServerAddr == "" || t.AgentAddr == "" || t.Subnet == "" {
		return nil, fmt.Errorf("token is missing required fields")
	}
	return &t, nil
}

func checksum(t Token) string {
	payload := fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s:%d:%d",
		t.Version, t.ServerPub, t.Endpoint, t.ServerAddr, t.AgentAddr,
		t.Subnet, t.Interface, t.MTU, t.ListenPort)
	h := sha256.Sum256([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h[:8])
}
