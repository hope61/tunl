#!/bin/bash
set -euo pipefail

# Clean shared volume from previous runs
rm -f /shared/*

# Trigger nf_tables kernel module loading
nft list tables >/dev/null 2>&1 || true

echo "[vps] Initializing server..."
tunl server init --endpoint "172.31.0.10:51821" 2>&1 | tee /tmp/init-output.txt

# Extract and save the join token for the home container
TOKEN=$(grep "tunl join" /tmp/init-output.txt | awk '{print $NF}')
echo "$TOKEN" > /shared/join-token

echo "[vps] Waiting for agent key..."
for i in $(seq 1 30); do
    if [ -f /shared/agent-key ]; then
        break
    fi
    sleep 1
done

if [ ! -f /shared/agent-key ]; then
    echo "[vps] ERROR: agent key not found after 30s"
    exit 1
fi

AGENT_KEY=$(cat /shared/agent-key)
echo "[vps] Allowing agent: $AGENT_KEY"
tunl server allow "$AGENT_KEY"

echo "[vps] Waiting for expose signal..."
for i in $(seq 1 30); do
    if [ -f /shared/exposed ]; then
        break
    fi
    sleep 1
done

echo "[vps] Adding forward 25565/tcp..."
tunl add 25565/tcp --name minecraft

echo "[vps] Waiting for WireGuard handshake..."
for i in $(seq 1 45); do
    TS=$(wg show tunl0 latest-handshakes 2>/dev/null | awk '{print $2}' || true)
    if [ -n "$TS" ] && [ "$TS" != "0" ]; then
        echo "[vps] Handshake established (timestamp: $TS)"
        break
    fi
    # Ping triggers WG to try sending, which queues a handshake
    ping -c1 -W1 10.77.0.2 >/dev/null 2>&1 || true
    sleep 1
done
echo "[vps] WG state after handshake wait:"
wg show tunl0 2>/dev/null || true

# Write debug info for client to read
{
    echo "=== VPS nft list ruleset ==="
    nft list ruleset 2>/dev/null || true
    echo ""
    echo "=== VPS ip route ==="
    ip route 2>/dev/null || true
    echo ""
    echo "=== VPS ip addr ==="
    ip addr 2>/dev/null || true
    echo ""
    echo "=== VPS ping agent tunnel ==="
    ping -c2 -W2 10.77.0.2 2>&1 || true
    echo ""
    echo "=== VPS iptables -L ==="
    iptables -L -n 2>/dev/null || true
} > /shared/vps-debug

touch /shared/forward-ready

echo "[vps] Waiting for snat-test signal..."
for i in $(seq 1 60); do
    if [ -f /shared/snat-test ]; then
        break
    fi
    sleep 1
done

echo "[vps] Switching to SNAT mode..."
tunl remove 25565/tcp
tunl add 25565/tcp --name minecraft --snat
touch /shared/snat-ready

echo "[vps] Waiting for teardown signal..."
for i in $(seq 1 60); do
    if [ -f /shared/teardown ]; then
        break
    fi
    sleep 1
done

echo "[vps] Running down..."
tunl down
touch /shared/vps-down

echo "[vps] Waiting for uninstall signal..."
for i in $(seq 1 60); do
    if [ -f /shared/do-uninstall ]; then
        break
    fi
    sleep 1
done

tunl up
tunl uninstall
touch /shared/vps-uninstalled

sleep infinity
