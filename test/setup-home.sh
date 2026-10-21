#!/bin/bash
set -euo pipefail

# Trigger nf_tables kernel module loading
nft list tables >/dev/null 2>&1 || true

echo "[home] Waiting for join token..."
for i in $(seq 1 30); do
    if [ -f /shared/join-token ]; then
        break
    fi
    sleep 1
done

if [ ! -f /shared/join-token ]; then
    echo "[home] ERROR: join token not found after 30s"
    exit 1
fi

TOKEN=$(cat /shared/join-token)
echo "[home] Joining server..."
tunl join "$TOKEN" 2>&1 | tee /tmp/join-output.txt

AGENT_KEY=$(grep "tunl server allow" /tmp/join-output.txt | awk '{print $NF}')
echo "$AGENT_KEY" > /shared/agent-key

sleep 3

echo "[home] Exposing port 25565/tcp..."
tunl expose 25565/tcp
touch /shared/exposed

echo "[home] Starting echo server on port 25565..."
socat TCP-LISTEN:25565,reuseaddr,fork EXEC:"/bin/bash -c 'echo \$SOCAT_PEERADDR'" &

echo "[home] Debug: WG state:"
wg show tunl0 2>/dev/null || true
echo "[home] Debug: nft list ruleset:"
nft list ruleset 2>/dev/null || true
echo "[home] Debug: ip route:"
ip route 2>/dev/null || true
echo "[home] Debug: ip rule:"
ip rule 2>/dev/null || true
echo "[home] Debug: ip route show table 100:"
ip route show table 100 2>/dev/null || true
echo "[home] Debug: ping server tunnel IP:"
ping -c2 -W2 10.77.0.1 2>&1 || true

echo "[home] Waiting for teardown signal..."
for i in $(seq 1 120); do
    if [ -f /shared/teardown ]; then
        break
    fi
    sleep 1
done

echo "[home] Running down..."
tunl down
touch /shared/home-down

echo "[home] Waiting for uninstall signal..."
for i in $(seq 1 60); do
    if [ -f /shared/do-uninstall ]; then
        break
    fi
    sleep 1
done

tunl up
tunl uninstall
touch /shared/home-uninstalled

sleep infinity
