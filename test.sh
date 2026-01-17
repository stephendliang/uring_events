#!/bin/bash
#
# test.sh - Build, validate, and test the raw io_uring HTTP server
#
# This script:
#   1. Validates source code for critical patterns (catches common mistakes)
#   2. Builds with maximum optimizations
#   3. Runs the server
#   4. Tests with curl (single + concurrent)
#   5. Reports results
#
# Usage: ./test.sh [port] [cpu]
#        ./test.sh              # defaults: port=8080, cpu=0
#        ./test.sh 9000 1       # port 9000, cpu 1
#

set -e

# =============================================================================
# Configuration
# =============================================================================

PORT="${1:-8080}"
CPU="${2:-0}"
SOURCE="event.c"
BINARY="event"
CC="${CC:-gcc}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper functions
# =============================================================================

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_fatal() { echo -e "${RED}[FATAL]${NC} $1"; exit 1; }

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Stopping server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# =============================================================================
# Phase 1: Source Code Validation
# =============================================================================

validate_source() {
    echo ""
    echo "=============================================="
    echo " PHASE 1: Source Code Validation"
    echo "=============================================="

    local errors=0

    if [ ! -f "$SOURCE" ]; then
        log_fatal "Source file '$SOURCE' not found!"
    fi

    log_info "Checking $SOURCE for critical patterns..."

    # ---------------------------------------------------------------------
    # CHECK 1: Multishot recv must have len=0
    # Your friend's mistake: adding length breaks multishot recv
    # ---------------------------------------------------------------------
    if grep -n "prep_recv_multishot" "$SOURCE" | head -1 > /dev/null; then
        # Find the function and check sqe->len
        local recv_func=$(awk '/prep_recv_multishot/,/^}/' "$SOURCE")
        if echo "$recv_func" | grep -q 'sqe->len[[:space:]]*=[[:space:]]*[1-9]'; then
            log_error "CRITICAL: prep_recv_multishot has non-zero len!"
            log_error "         Multishot recv MUST have sqe->len = 0"
            log_error "         This will cause recv to fail silently!"
            errors=$((errors + 1))
        elif echo "$recv_func" | grep -q 'sqe->len[[:space:]]*=[[:space:]]*0'; then
            log_ok "Multishot recv has len=0 (correct)"
        else
            log_warn "Could not verify recv multishot len value"
        fi
    fi

    # ---------------------------------------------------------------------
    # CHECK 2: No liburing includes (we don't use liburing)
    # ---------------------------------------------------------------------
    if grep -n '#include.*<liburing' "$SOURCE" > /dev/null 2>&1; then
        log_error "CRITICAL: Found liburing include!"
        log_error "         This server uses raw io_uring syscalls, not liburing"
        grep -n '#include.*<liburing' "$SOURCE"
        errors=$((errors + 1))
    else
        log_ok "No liburing dependency (correct - raw syscalls)"
    fi

    # ---------------------------------------------------------------------
    # CHECK 3: Required io_uring flags must be present
    # ---------------------------------------------------------------------
    local required_flags=(
        "IORING_SETUP_SUBMIT_ALL"
        "IORING_SETUP_SINGLE_ISSUER"
        "IORING_SETUP_DEFER_TASKRUN"
        "IORING_SETUP_COOP_TASKRUN"
    )

    for flag in "${required_flags[@]}"; do
        if grep -q "$flag" "$SOURCE"; then
            log_ok "Found $flag"
        else
            log_error "MISSING: $flag not found in source!"
            log_error "         This flag is required per CLAUDE.md architecture"
            errors=$((errors + 1))
        fi
    done

    # ---------------------------------------------------------------------
    # CHECK 4: Multishot accept must be present
    # ---------------------------------------------------------------------
    if grep -q "IORING_ACCEPT_MULTISHOT" "$SOURCE"; then
        log_ok "Multishot accept enabled"
    else
        log_error "MISSING: IORING_ACCEPT_MULTISHOT not found!"
        errors=$((errors + 1))
    fi

    # ---------------------------------------------------------------------
    # CHECK 5: Multishot recv must be present
    # ---------------------------------------------------------------------
    if grep -q "IORING_RECV_MULTISHOT" "$SOURCE"; then
        log_ok "Multishot recv enabled"
    else
        log_error "MISSING: IORING_RECV_MULTISHOT not found!"
        errors=$((errors + 1))
    fi

    # ---------------------------------------------------------------------
    # CHECK 6: Buffer select must be present (for provided buffers)
    # ---------------------------------------------------------------------
    if grep -q "IOSQE_BUFFER_SELECT" "$SOURCE"; then
        log_ok "Buffer select enabled (provided buffer ring)"
    else
        log_error "MISSING: IOSQE_BUFFER_SELECT not found!"
        errors=$((errors + 1))
    fi

    # ---------------------------------------------------------------------
    # CHECK 7: TCP_NODELAY should be set
    # ---------------------------------------------------------------------
    if grep -q "TCP_NODELAY" "$SOURCE"; then
        log_ok "TCP_NODELAY found"
    else
        log_warn "TCP_NODELAY not found (recommended per CLAUDE.md)"
    fi

    # ---------------------------------------------------------------------
    # CHECK 8: No SQPOLL (explicitly avoided per CLAUDE.md)
    # ---------------------------------------------------------------------
    if grep -q "IORING_SETUP_SQPOLL" "$SOURCE"; then
        log_warn "SQPOLL found - per CLAUDE.md this should be avoided"
        log_warn "         'Kernel polling threads burn CPU and fight for cache'"
    else
        log_ok "No SQPOLL (correct per CLAUDE.md)"
    fi

    # ---------------------------------------------------------------------
    # CHECK 9: HTTP response exists
    # ---------------------------------------------------------------------
    if grep -q "HTTP/1.1 200" "$SOURCE"; then
        log_ok "HTTP 200 response found"
    else
        log_error "No HTTP 200 response found in source!"
        errors=$((errors + 1))
    fi

    # ---------------------------------------------------------------------
    # CHECK 10: Memory barriers present (for correct ring operation)
    # ---------------------------------------------------------------------
    if grep -q "ATOMIC_ACQUIRE\|ATOMIC_RELEASE\|smp_load_acquire\|smp_store_release" "$SOURCE"; then
        log_ok "Memory barriers present"
    else
        log_warn "No memory barriers found - may cause race conditions"
    fi

    echo ""
    if [ $errors -gt 0 ]; then
        log_fatal "Source validation failed with $errors error(s)!"
    else
        log_ok "Source validation passed!"
    fi
}

# =============================================================================
# Phase 2: Build
# =============================================================================

build_server() {
    echo ""
    echo "=============================================="
    echo " PHASE 2: Build"
    echo "=============================================="

    log_info "Compiler: $($CC --version | head -1)"

    # Optimization flags per run.sh
    local OPT_FLAGS=(
        -O3
        -march=native
        -mtune=native
        -fomit-frame-pointer
        -fno-stack-protector
        -fno-plt
        -flto
        -fno-semantic-interposition
        -fvisibility=hidden
        -DNDEBUG
    )

    log_info "Building with: ${OPT_FLAGS[*]}"

    if $CC -std=gnu11 -Wall -Wextra -Werror "${OPT_FLAGS[@]}" "$SOURCE" -o "$BINARY" 2>&1; then
        log_ok "Build succeeded!"
        ls -la "$BINARY"
    else
        log_fatal "Build failed!"
    fi
}

# =============================================================================
# Phase 3: Run Server
# =============================================================================

start_server() {
    echo ""
    echo "=============================================="
    echo " PHASE 3: Start Server"
    echo "=============================================="

    # Kill any existing instance
    pkill -9 "$BINARY" 2>/dev/null || true
    sleep 0.3

    log_info "Starting server on port $PORT, CPU $CPU..."

    ./"$BINARY" "$PORT" "$CPU" &
    SERVER_PID=$!

    # Wait for server to start
    sleep 0.5

    if kill -0 "$SERVER_PID" 2>/dev/null; then
        log_ok "Server started (PID: $SERVER_PID)"
    else
        log_fatal "Server failed to start!"
    fi

    # Check if port is listening
    if command -v ss &> /dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":$PORT"; then
            log_ok "Server listening on port $PORT"
        else
            log_warn "Could not verify port $PORT is listening"
        fi
    fi
}

# =============================================================================
# Phase 4: Test
# =============================================================================

test_server() {
    echo ""
    echo "=============================================="
    echo " PHASE 4: Tests"
    echo "=============================================="

    local test_failures=0

    # -------------------------------------------------------------------------
    # TEST 1: Basic HTTP request
    # -------------------------------------------------------------------------
    log_info "Test 1: Basic HTTP request..."

    local response
    response=$(curl -s -w "\n%{http_code}" "http://localhost:$PORT/" 2>&1)
    local body=$(echo "$response" | head -n -1)
    local code=$(echo "$response" | tail -1)

    if [ "$code" = "200" ]; then
        log_ok "HTTP 200 OK received"
        log_info "Response body: '$body'"
    else
        log_error "Expected HTTP 200, got: $code"
        log_error "Response: $response"
        test_failures=$((test_failures + 1))
    fi

    # -------------------------------------------------------------------------
    # TEST 2: Multiple sequential requests
    # -------------------------------------------------------------------------
    log_info "Test 2: Sequential requests (10x)..."

    local success=0
    for i in {1..10}; do
        if curl -s "http://localhost:$PORT/" > /dev/null 2>&1; then
            success=$((success + 1))
        fi
    done

    if [ $success -eq 10 ]; then
        log_ok "All 10 sequential requests succeeded"
    else
        log_error "Only $success/10 sequential requests succeeded"
        test_failures=$((test_failures + 1))
    fi

    # -------------------------------------------------------------------------
    # TEST 3: Concurrent requests
    # -------------------------------------------------------------------------
    log_info "Test 3: Concurrent requests (20 parallel)..."

    local pids=()
    local concurrent_results="/tmp/uring_test_$$"
    mkdir -p "$concurrent_results"

    for i in {1..20}; do
        (
            if curl -s "http://localhost:$PORT/" > /dev/null 2>&1; then
                echo "ok" > "$concurrent_results/$i"
            else
                echo "fail" > "$concurrent_results/$i"
            fi
        ) &
        pids+=($!)
    done

    # Wait for all
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    local concurrent_ok=$(grep -l "ok" "$concurrent_results"/* 2>/dev/null | wc -l)
    rm -rf "$concurrent_results"

    if [ "$concurrent_ok" -eq 20 ]; then
        log_ok "All 20 concurrent requests succeeded"
    else
        log_error "Only $concurrent_ok/20 concurrent requests succeeded"
        test_failures=$((test_failures + 1))
    fi

    # -------------------------------------------------------------------------
    # TEST 4: Keep-alive (multiple requests on same connection)
    # -------------------------------------------------------------------------
    log_info "Test 4: Keep-alive (5 requests, 1 connection)..."

    local keepalive_response
    keepalive_response=$(curl -s "http://localhost:$PORT/" \
                              "http://localhost:$PORT/" \
                              "http://localhost:$PORT/" \
                              "http://localhost:$PORT/" \
                              "http://localhost:$PORT/" 2>&1)

    # Count occurrences of "OK" (response body is "OK" so count the pairs)
    local ok_count=$(echo "$keepalive_response" | grep -o "OK" | wc -l)

    if [ "$ok_count" -ge 5 ]; then
        log_ok "Keep-alive working ($ok_count responses)"
    else
        log_error "Keep-alive may not be working (got $ok_count responses, expected 5)"
        log_error "Response was: '$keepalive_response'"
        test_failures=$((test_failures + 1))
    fi

    # -------------------------------------------------------------------------
    # TEST 5: Response time check
    # -------------------------------------------------------------------------
    log_info "Test 5: Response time..."

    local time_output
    time_output=$(curl -s -o /dev/null -w "%{time_total}" "http://localhost:$PORT/" 2>&1)

    log_info "Response time: ${time_output}s"

    # Check if under 100ms (should be way faster)
    local time_ms=$(echo "$time_output * 1000" | bc 2>/dev/null || echo "0")
    if [ -n "$time_ms" ] && [ "${time_ms%.*}" -lt 100 ]; then
        log_ok "Response time under 100ms"
    else
        log_warn "Response time >= 100ms (may indicate issues)"
    fi

    # -------------------------------------------------------------------------
    # TEST 6: Server still running after all tests
    # -------------------------------------------------------------------------
    log_info "Test 6: Server stability check..."

    if kill -0 "$SERVER_PID" 2>/dev/null; then
        log_ok "Server still running after tests"
    else
        log_error "Server crashed during tests!"
        test_failures=$((test_failures + 1))
    fi

    # -------------------------------------------------------------------------
    # Results
    # -------------------------------------------------------------------------
    echo ""
    if [ $test_failures -eq 0 ]; then
        log_ok "All tests passed!"
    else
        log_error "$test_failures test(s) failed!"
    fi

    return $test_failures
}

# =============================================================================
# Phase 5: Report
# =============================================================================

report() {
    echo ""
    echo "=============================================="
    echo " PHASE 5: Report"
    echo "=============================================="

    if kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Server process info:"
        ps -o pid,comm,rss,vsz,%cpu -p "$SERVER_PID" 2>/dev/null || true

        echo ""
        log_info "Memory breakdown:"
        echo "  RSS (Resident Set Size): $(ps -o rss= -p "$SERVER_PID" 2>/dev/null || echo "?") KB"
        echo "  VSZ (Virtual Size): $(ps -o vsz= -p "$SERVER_PID" 2>/dev/null || echo "?") KB"
    fi

    echo ""
    log_info "Binary info:"
    ls -la "$BINARY"
    file "$BINARY"

    echo ""
    log_info "To stop the server: kill $SERVER_PID"
    log_info "To test manually: curl http://localhost:$PORT/"
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "=============================================="
    echo " Raw io_uring HTTP Server - Test Suite"
    echo "=============================================="
    echo " Port: $PORT"
    echo " CPU:  $CPU"
    echo "=============================================="

    validate_source
    build_server
    start_server

    if test_server; then
        report
        echo ""
        echo -e "${GREEN}=============================================="
        echo " ALL CHECKS PASSED - SERVER IS OPERATIONAL"
        echo "==============================================${NC}"
        echo ""
        exit 0
    else
        echo ""
        echo -e "${RED}=============================================="
        echo " TESTS FAILED - CHECK OUTPUT ABOVE"
        echo "==============================================${NC}"
        echo ""
        exit 1
    fi
}

main "$@"
