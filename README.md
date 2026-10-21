# tunl

Expose TCP/UDP ports from a home server to the internet through a VPS over WireGuard, without revealing your home IP. One static binary, no daemon, no control plane.

## How it works

```
Internet → VPS (public IP) → WireGuard tunnel → Home server
```

- **Agent** (home) connects outward to the VPS — no ports opened on the home router.
- **Server** (VPS) DNATs incoming traffic through the tunnel to the agent.
- By default, the home server sees real client IPs (no masquerade).
- Kernel WireGuard and nftables hold all state. `tunl up` applies config; a systemd oneshot runs it at boot.

## Quickstart

```bash
# 1. Build
make build

# 2. On the VPS
tunl server init --endpoint vps.example.com:51821

# 3. On the home machine (copy the token from step 2)
tunl join <token>

# 4. On the VPS (copy the key from step 3)
tunl server allow <agent-public-key>

# 5. Forward a port
tunl expose 25565/tcp         # on home
tunl add 25565/tcp --name mc  # on VPS
```

That's it. Minecraft players connect to `vps.example.com:25565` and your home IP stays hidden.

## Requirements

- Linux with kernel WireGuard (`wireguard` module loaded)
- Root / `CAP_NET_ADMIN`
- nftables (kernel support)

## CLI reference

### Server (VPS)

| Command | Description |
|---------|-------------|
| `tunl server init --endpoint <host:port>` | Initialize server, generate join token |
| `tunl server allow <agent-public-key>` | Authorize the agent |
| `tunl add <port/proto> [--to <port>] [--name <label>] [--snat]` | Add a port forward |
| `tunl remove <port/proto>` | Remove a port forward |

### Agent (home)

| Command | Description |
|---------|-------------|
| `tunl join <token>` | Join a server using the join token |
| `tunl expose <port/proto>` | Allow a port through the tunnel firewall |
| `tunl unexpose <port/proto>` | Block a port through the tunnel firewall |

### Both

| Command | Description |
|---------|-------------|
| `tunl up` | Apply tunnel config (idempotent) |
| `tunl down` | Tear down tunnel |
| `tunl status` | Show tunnel status |
| `tunl list` | List port forwards |
| `tunl doctor` | Run diagnostic checks |
| `tunl uninstall` | Remove everything tunl created |

## Port forwarding

```bash
# Forward port 25565 TCP to the agent
tunl add 25565/tcp --name minecraft

# Forward with port remapping (VPS 8080 → agent 80)
tunl add 8080/tcp --to 80 --name web

# Forward with SNAT (agent sees tunnel IP instead of real client IP)
tunl add 25565/tcp --name minecraft --snat
```

On the agent side, you must explicitly expose each port:

```bash
tunl expose 25565/tcp
```

The agent firewall drops all tunnel traffic except exposed ports, even if the VPS is compromised.

## Troubleshooting

Run `tunl doctor` for automated checks. Common issues:

### No WireGuard handshake
- Check that the VPS endpoint is reachable: `nc -zuv vps.example.com 51821`
- Verify the agent key is authorized: `tunl server allow <key>`
- If using Cloudflare DNS, set the record to "DNS only" (grey cloud)

### Forwarding doesn't work
- Ensure the port is exposed on the agent: `tunl expose <port/proto>`
- Ensure the port is added on the server: `tunl add <port/proto>`
- Check the service is listening: `ss -tlnp | grep <port>`
- Check for conflicting firewalls: `tunl doctor` will detect ufw/Docker FORWARD drops

### UFW or Docker blocking forwarded traffic
`tunl doctor` will print the exact fix command, e.g.:
```bash
ufw route allow in on eth0 out on tunl0 to 10.77.0.2 port 25565 proto tcp
```

### MTU issues (connections hang after handshake)
The default MTU is 1420 with TCP MSS clamping. If you still see hangs, try lowering:
```bash
tunl server init --endpoint host:port --mtu 1380
```

## Defaults

| Setting | Default |
|---------|---------|
| Interface | `tunl0` |
| WireGuard port | `51821` |
| Subnet | `10.77.0.0/24` |
| MTU | `1420` |
| Config path | `/etc/tunl/config.json` |

All configurable during `server init` / `join`.

## Uninstall

```bash
tunl uninstall
```

This removes:
- WireGuard interface (`tunl0`)
- nftables table (`inet tunl`)
- IP rules and routes
- Systemd unit
- Sysctl config (`/etc/sysctl.d/99-tunl.conf`)
- Config directory (`/etc/tunl/`)

IP forwarding is left enabled if other software (e.g. Docker) may depend on it.

## Building

```bash
make build          # static Linux binary
make test           # unit tests
make lint           # go vet, staticcheck, gosec, govulncheck
make test-docker    # full test suite in Docker (unit + integration)
```

## Security

- Private keys never leave the machine that generated them
- Join tokens contain only public data (server pubkey, endpoint, tunnel IPs)
- Agent firewall drops all tunnel traffic except explicitly exposed ports
- All firewall rules are in a dedicated `inet tunl` table — other tables are never modified
- No network listeners except the WireGuard UDP port
- No shell command execution — all network setup uses netlink libraries
- Config files are root-owned with `0600`/`0700` permissions
