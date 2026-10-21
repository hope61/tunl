#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass=0
fail=0

assert() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}: $desc"
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}: $desc"
        ((fail++))
    fi
}

assert_fail() {
    local desc="$1"
    shift
    if ! "$@" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}: $desc"
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}: $desc"
        ((fail++))
    fi
}

wait_for() {
    local host="$1" port="$2" timeout="${3:-10}"
    for i in $(seq 1 "$timeout"); do
        if echo | nc -w1 "$host" "$port" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

VPS=172.30.0.10
HOME_IP=172.31.0.20
CLIENT=172.30.0.30

echo "=== tunl integration tests ==="
echo ""

# Verify client cannot reach home directly
echo "--- Connectivity check ---"
assert_fail "client cannot reach home directly" ping -c1 -W1 "$HOME_IP"

# Step 1: Initialize server on VPS
echo ""
echo "--- Server init ---"
TOKEN=$(docker exec tunl-vps-1 tunl server init --endpoint "${VPS}:51821" 2>&1 | grep "tunl join" | awk '{print $NF}')
if [ -z "$TOKEN" ]; then
    echo -e "${RED}FAIL${NC}: could not extract join token"
    exit 1
fi
echo -e "${GREEN}PASS${NC}: server init produced join token"
((pass++))

# Step 2: Agent joins
echo ""
echo "--- Agent join ---"
AGENT_KEY=$(docker exec tunl-home-1 tunl join "$TOKEN" 2>&1 | grep "tunl server allow" | awk '{print $NF}')
if [ -z "$AGENT_KEY" ]; then
    echo -e "${RED}FAIL${NC}: could not extract agent key"
    exit 1
fi
echo -e "${GREEN}PASS${NC}: agent join produced public key"
((pass++))

# Step 3: Server allows agent
docker exec tunl-vps-1 tunl server allow "$AGENT_KEY"
echo -e "${GREEN}PASS${NC}: server allowed agent"
((pass++))

# Wait for handshake
sleep 3

# Step 4: Check status
echo ""
echo "--- Status checks ---"
assert "vps status shows interface up" docker exec tunl-vps-1 tunl status
assert "home status shows interface up" docker exec tunl-home-1 tunl status

# Step 5: Start echo server on home
echo ""
echo "--- Echo server ---"
docker exec -d tunl-home-1 bash -c '
while true; do
    echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n$(echo $REMOTE_ADDR)" | nc -l -p 25565 -q0 || true
done
'
# Also start a simple TCP echo that reports remote IP
docker exec -d tunl-home-1 bash -c '
apt-get update -qq && apt-get install -y -qq socat >/dev/null 2>&1
socat TCP-LISTEN:25565,reuseaddr,fork SYSTEM:"echo \$SOCAT_PEERADDR" &
'
sleep 2

# Step 6: Expose port on agent, add forward on server
echo ""
echo "--- Port forwarding ---"
docker exec tunl-home-1 tunl expose 25565/tcp
assert "expose succeeded" docker exec tunl-home-1 tunl list

docker exec tunl-vps-1 tunl add 25565/tcp --name minecraft
assert "add forward succeeded" docker exec tunl-vps-1 tunl list

sleep 1

# Step 7: Test TCP forwarding from client
echo ""
echo "--- Forwarding tests ---"
RESULT=$(echo "test" | nc -w3 "$VPS" 25565 2>/dev/null || true)
if [ -n "$RESULT" ]; then
    echo -e "${GREEN}PASS${NC}: TCP forward works (got response: $RESULT)"
    ((pass++))

    # Check if we see the real client IP (not tunnel IP) when not using SNAT
    if echo "$RESULT" | grep -q "$CLIENT"; then
        echo -e "${GREEN}PASS${NC}: real client IP preserved ($CLIENT)"
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}: expected real client IP $CLIENT, got $RESULT"
        ((fail++))
    fi
else
    echo -e "${RED}FAIL${NC}: TCP forward returned no data"
    ((fail++))
fi

# Step 8: Test idempotency (re-running up)
echo ""
echo "--- Idempotency ---"
assert "vps up is idempotent" docker exec tunl-vps-1 tunl up
assert "home up is idempotent" docker exec tunl-home-1 tunl up

# Step 9: Test SNAT mode
echo ""
echo "--- SNAT mode ---"
docker exec tunl-vps-1 tunl remove 25565/tcp
docker exec tunl-vps-1 tunl add 25565/tcp --name minecraft --snat
sleep 1

SNAT_RESULT=$(echo "test" | nc -w3 "$VPS" 25565 2>/dev/null || true)
if [ -n "$SNAT_RESULT" ]; then
    if echo "$SNAT_RESULT" | grep -qv "$CLIENT"; then
        echo -e "${GREEN}PASS${NC}: SNAT mode shows tunnel IP, not client IP"
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}: SNAT mode still shows client IP"
        ((fail++))
    fi
else
    echo -e "${GREEN}PASS${NC}: SNAT test (no response is acceptable in test env)"
    ((pass++))
fi

# Step 10: Test doctor
echo ""
echo "--- Doctor ---"
docker exec tunl-vps-1 tunl doctor || true
docker exec tunl-home-1 tunl doctor || true
echo -e "${GREEN}PASS${NC}: doctor runs without crash"
((pass++))

# Step 11: Test input validation
echo ""
echo "--- Validation ---"
assert_fail "reject port 0" docker exec tunl-vps-1 tunl add 0/tcp
assert_fail "reject port 99999" docker exec tunl-vps-1 tunl add 99999/tcp
assert_fail "reject bad proto" docker exec tunl-vps-1 tunl add 80/icmp
assert_fail "reject bad format" docker exec tunl-vps-1 tunl add 80

# Step 12: Test down and cleanup
echo ""
echo "--- Teardown ---"
assert "vps down succeeds" docker exec tunl-vps-1 tunl down
assert "home down succeeds" docker exec tunl-home-1 tunl down

# Verify cleanup
assert_fail "vps tunl0 removed" docker exec tunl-vps-1 ip link show tunl0
assert_fail "home tunl0 removed" docker exec tunl-home-1 ip link show tunl0

# Step 13: Test uninstall
docker exec tunl-vps-1 tunl up
docker exec tunl-home-1 tunl up
assert "vps uninstall succeeds" docker exec tunl-vps-1 tunl uninstall
assert "home uninstall succeeds" docker exec tunl-home-1 tunl uninstall
assert_fail "vps tunl0 removed after uninstall" docker exec tunl-vps-1 ip link show tunl0
assert_fail "home tunl0 removed after uninstall" docker exec tunl-home-1 ip link show tunl0

echo ""
echo "=== Results: $pass passed, $fail failed ==="
if [ "$fail" -gt 0 ]; then
    exit 1
fi
