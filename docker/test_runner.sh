#!/bin/bash
# peekaboo — Docker Test Runner
# Builds, deploys, and runs comprehensive tests across multiple scenarios

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BRAIN_DIR="$SCRIPT_DIR/../brain"
PEEKABOO_BIN="$PROJECT_DIR/peekaboo"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# ============================================================
# STEP 1: Build peekaboo binary
# ============================================================
log "Building peekaboo binary..."
cd "$PROJECT_DIR"
go build -o "$PEEKABOO_BIN" . || { fail "Build failed"; exit 1; }
pass "Binary built: $PEEKABOO_BIN"

# ============================================================
# STEP 2: Run local unit tests
# ============================================================
log "Running unit tests..."
go test -v ./... 2>&1 | tee "$BRAIN_DIR/test_results_unit.log" || warn "Some unit tests failed"

# ============================================================
# STEP 3: Build Docker images
# ============================================================
log "Building Docker test images..."
cd "$SCRIPT_DIR"

# Copy binary to docker context
cp "$PEEKABOO_BIN" "$SCRIPT_DIR/../peekaboo"

docker compose build --no-cache 2>&1 | tee "$BRAIN_DIR/docker_build.log" || { fail "Docker build failed"; exit 1; }
pass "Docker images built"

# ============================================================
# STEP 4: Start containers
# ============================================================
log "Starting test containers..."
docker compose up -d 2>&1 | tee "$BRAIN_DIR/docker_up.log"
sleep 3
pass "Containers started"

# ============================================================
# STEP 5: Test — Vulnerable System
# ============================================================
log "=== TEST: Vulnerable System ==="

log "Running scan-only mode..."
docker exec peekaboo-vulnerable peekaboo 2>&1 | tee "$BRAIN_DIR/test_vulnerable_scan.log"
echo ""

log "Running scan + enumerate..."
docker exec peekaboo-vulnerable peekaboo --vector suid 2>&1 | tee "$BRAIN_DIR/test_vulnerable_suid.log"
echo ""

log "Running JSON output..."
docker exec peekaboo-vulnerable peekaboo --json 2>&1 | tee "$BRAIN_DIR/test_vulnerable_json.log"
echo ""

log "Running quiet mode..."
docker exec peekaboo-vulnerable peekaboo --quiet 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 1 ]; then
    pass "Quiet mode exited with code $EXIT_CODE"
else
    fail "Quiet mode unexpected exit code: $EXIT_CODE"
fi
echo ""

# ============================================================
# STEP 6: Test — Clean System (should find minimal/no vectors)
# ============================================================
log "=== TEST: Clean System ==="

log "Running scan on clean system..."
docker exec peekaboo-clean peekaboo 2>&1 | tee "$BRAIN_DIR/test_clean_scan.log"
echo ""

log "Running JSON output on clean system..."
docker exec peekaboo-clean peekaboo --json 2>&1 | tee "$BRAIN_DIR/test_clean_json.log"
echo ""

# ============================================================
# STEP 7: Test — Edge Cases System
# ============================================================
log "=== TEST: Edge Cases System ==="

log "Running scan on edge cases system..."
docker exec peekaboo-edgecases peekaboo 2>&1 | tee "$BRAIN_DIR/test_edgecases_scan.log"
echo ""

log "Testing specific vectors..."
for vector in suid sudo cron passwd; do
    log "  Vector: $vector"
    docker exec peekaboo-edgecases peekaboo --vector "$vector" 2>&1 | tee -a "$BRAIN_DIR/test_edgecases_vectors.log"
    echo ""
done

# ============================================================
# STEP 8: Test — Help and Flags
# ============================================================
log "=== TEST: CLI Flags ==="

log "Testing --help..."
docker exec peekaboo-vulnerable peekaboo --help 2>&1 | tee "$BRAIN_DIR/test_help.log"
echo ""

log "Testing --risk levels..."
for risk in safe low medium high danger; do
    log "  Risk: $risk"
    docker exec peekaboo-vulnerable peekaboo --risk "$risk" 2>&1 | head -5
done
echo ""

log "Testing --one-shot..."
docker exec peekaboo-vulnerable peekaboo --one-shot 2>&1 | head -10
echo ""

log "Testing --stealth..."
timeout 10 docker exec peekaboo-vulnerable peekaboo --stealth 2>&1 | head -5 || true
echo ""

# ============================================================
# STEP 9: Cleanup
# ============================================================
log "Cleaning up..."
docker compose down -v 2>&1 | tee "$BRAIN_DIR/docker_down.log"
pass "Containers stopped"

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================"
echo "  Test Run Complete"
echo "============================================"
echo ""
echo "Results saved to: $BRAIN_DIR/"
echo ""
echo "Files generated:"
ls -la "$BRAIN_DIR/test_"*.log 2>/dev/null || echo "  (no test logs found)"
echo ""
