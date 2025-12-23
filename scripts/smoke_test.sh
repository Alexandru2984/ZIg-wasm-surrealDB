#!/bin/bash
# Smoke Test Script for Zig Task Manager
# Run after any changes to verify basic functionality
# Usage: ./scripts/smoke_test.sh [BASE_URL]

BASE_URL="${1:-http://127.0.0.1:9000}"
PASS=0
FAIL=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=================================="
echo "  🦎 Zig Task Manager Smoke Test"
echo "=================================="
echo "Base URL: $BASE_URL"
echo ""

# Helper function
test_endpoint() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local data="$4"
    local expected="$5"
    
    echo -n "Testing $name... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s "$BASE_URL$endpoint" 2>&1)
    else
        response=$(curl -s -X "$method" "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data" 2>&1)
    fi
    
    if echo "$response" | grep -q "$expected" 2>/dev/null; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASS=$((PASS + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "  Expected: $expected"
        echo "  Got: ${response:0:100}..."
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Helper to check header
test_header() {
    local name="$1"
    local endpoint="$2"
    local header="$3"
    local expected="$4"
    
    echo -n "Testing $name... "
    
    response=$(curl -sI "$BASE_URL$endpoint" 2>&1)
    
    if echo "$response" | grep -qi "$header.*$expected" 2>/dev/null; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASS=$((PASS + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "  Expected header: $header: $expected"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

echo "=== Core Endpoints ==="
test_endpoint "Health Check" "GET" "/api/health" "" "healthy" || true
test_endpoint "Ready Check" "GET" "/api/ready" "" "ready" || true
test_endpoint "Tasks (empty)" "GET" "/api/tasks" "" '\[\]' || true

echo ""
echo "=== Static Files ==="
test_endpoint "Index HTML" "GET" "/" "" "DOCTYPE" || true
test_header "Cache-Control (HTML)" "/" "Cache-Control" "no-cache" || true
test_header "Cache-Control (JS)" "/app.js" "Cache-Control" "max-age=3600" || true

echo ""
echo "=== Security Headers ==="
test_header "X-Content-Type-Options" "/" "X-Content-Type-Options" "nosniff" || true
test_header "X-Frame-Options" "/" "X-Frame-Options" "SAMEORIGIN" || true

echo ""
echo "=== Auth Endpoints ==="
test_endpoint "Login (bad creds)" "POST" "/api/auth/login" \
    '{"email":"test@test.com","password":"wrong"}' "Invalid credentials" || true

test_endpoint "Forgot Password" "POST" "/api/auth/forgot-password" \
    '{"email":"test@test.com"}' "success" || true

echo ""
echo "=== Path Security ==="
# Test path traversal protection
response=$(curl -s "$BASE_URL/../../etc/passwd" 2>&1)
if echo "$response" | grep -q "403\|404\|Forbidden\|Not Found" 2>/dev/null; then
    echo -e "Testing Path Traversal Block... ${GREEN}✓ PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "Testing Path Traversal Block... ${RED}✗ FAIL${NC}"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=================================="
echo "=== Summary ==="
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"
echo "=================================="

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed!${NC}"
    exit 1
fi
