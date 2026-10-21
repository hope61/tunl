package netsetup

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hope61/tunl/internal/config"
)

func CreateInterface(cfg *config.Config) error {
	link := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: cfg.Interface,
			MTU:  cfg.MTU,
		},
	}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("creating WireGuard interface %s: %w", cfg.Interface, err)
	}
	addr, err := netlink.ParseAddr(cfg.TunnelAddr + "/24")
	if err != nil {
		return fmt.Errorf("parsing tunnel address: %w", err)
	}
	_, subnet, _ := net.ParseCIDR(cfg.Subnet)
	addr.IPNet.Mask = subnet.Mask
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("adding address to %s: %w", cfg.Interface, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up %s: %w", cfg.Interface, err)
	}
	return nil
}

func ConfigureWireGuard(cfg *config.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("creating WireGuard client: %w", err)
	}
	defer client.Close()

	privKey, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &privKey,
		ReplacePeers: true,
	}

	if cfg.Role == config.RoleServer {
		wgCfg.ListenPort = &cfg.ListenPort
		if cfg.AllowedAgentKey != "" {
			peer, err := buildPeer(cfg.AllowedAgentKey, "", cfg.PeerAddr)
			if err != nil {
				return err
			}
			wgCfg.Peers = []wgtypes.PeerConfig{peer}
		}
	} else {
		peer, err := buildPeer(cfg.PeerPubKey, cfg.Endpoint, cfg.PeerAddr)
		if err != nil {
			return err
		}
		// Agent needs 0.0.0.0/0 in allowed IPs so reply traffic to arbitrary
		// client IPs can be routed back through the tunnel via policy routing.
		peer.AllowedIPs = []net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		}
		keepalive := 25 * time.Second
		peer.PersistentKeepaliveInterval = &keepalive
		wgCfg.Peers = []wgtypes.PeerConfig{peer}
	}

	if err := client.ConfigureDevice(cfg.Interface, wgCfg); err != nil {
		return fmt.Errorf("configuring WireGuard device: %w", err)
	}
	return nil
}

func buildPeer(pubKeyStr, endpoint, peerAddr string) (wgtypes.PeerConfig, error) {
	pubKey, err := wgtypes.ParseKey(pubKeyStr)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parsing peer public key: %w", err)
	}

	_, allowedNet, err := net.ParseCIDR(peerAddr + "/32")
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parsing peer address: %w", err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		AllowedIPs: []net.IPNet{*allowedNet},
	}

	if endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp4", endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("resolving endpoint %q: %w", endpoint, err)
		}
		peer.Endpoint = addr
	}

	return peer, nil
}

func RemoveInterface(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("removing interface %s: %w", ifaceName, err)
	}
	return nil
}

func InterfaceExists(ifaceName string) bool {
	_, err := netlink.LinkByName(ifaceName)
	return err == nil
}

func GenerateKeyPair() (privateKey, publicKey string, err error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generating WireGuard key: %w", err)
	}
	pub := priv.PublicKey()
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub[:]), nil
}

type PeerStatus struct {
	PublicKey    string
	Endpoint     string
	LastHandshake time.Time
	TransferRx   int64
	TransferTx   int64
	HandshakeAge time.Duration
}

func GetPeerStatus(ifaceName string) (*PeerStatus, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("creating WireGuard client: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("getting device %s: %w", ifaceName, err)
	}

	if len(dev.Peers) == 0 {
		return nil, nil
	}

	p := dev.Peers[0]
	status := &PeerStatus{
		PublicKey:     p.PublicKey.String(),
		LastHandshake: p.LastHandshakeTime,
		TransferRx:    p.ReceiveBytes,
		TransferTx:    p.TransmitBytes,
	}
	if p.Endpoint != nil {
		status.Endpoint = p.Endpoint.String()
	}
	if !p.LastHandshakeTime.IsZero() {
		status.HandshakeAge = time.Since(p.LastHandshakeTime)
	}
	return status, nil
}
