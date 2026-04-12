#!/bin/bash
# test_scoring.sh — Score thresholds and exit code tests
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SCD=./scd

assert_exit_code() {
    local desc="$1" input="$2" expected="$3"
    echo "$input" | $SCD >/dev/null 2>&1
    local actual=$?
    if [ "$actual" -eq "$expected" ]; then
        echo "  ✓ PASS: $desc (exit=$actual)"; ((PASS++)) || true
    else
        echo "  ✗ FAIL: $desc (expected exit=$expected, got=$actual)"
        ((FAIL++)) || true
    fi
}

assert_score_range() {
    local desc="$1" input="$2" label="$3"
    local actual
    actual=$(echo "$input" | $SCD -v 2>&1) || true
    if echo "$actual" | grep -qi "$label"; then
        echo "  ✓ PASS: $desc ($label)"; ((PASS++)) || true
    else
        echo "  ✗ FAIL: $desc (expected $label)"
        echo "    got: $actual"
        ((FAIL++)) || true
    fi
}

echo "═══════════════════════════════════════════"
echo " SCD Scoring & Exit Code Tests"
echo "═══════════════════════════════════════════"

# Clean command → exit 0
assert_exit_code "Clean exit 0"       "ls -la"         0

# LOW risk → score 15 → below default threshold 20 → exit 0
assert_exit_code "LOW below thresh"   "unset HISTFILE"  0

# MEDIUM risk → score 40 → suspicious → exit 1
assert_exit_code "MEDIUM suspicious"  "kill -9 1234"    1

# HIGH risk → score 70 → dangerous → exit 2
assert_exit_code "HIGH dangerous"     "sudo su"         2

# CRITICAL → score 100 → dangerous → exit 2
assert_exit_code "CRITICAL dangerous" "rm -rf /"        2

# Score labels
assert_score_range "clean label"       "ls -la"         "clean"
assert_score_range "suspicious label"  "kill -9 999"    "suspicious"
assert_score_range "dangerous label"   "rm -rf /"       "dangerous"

# Sample files
echo ""
echo "── Testing sample files ──"

$SCD tests/sample_clean.txt >/dev/null 2>&1
clean_exit=$?
if [ "$clean_exit" -eq 0 ]; then
    echo "  ✓ PASS: sample_clean.txt → exit 0"; ((PASS++)) || true
else
    echo "  ✗ FAIL: sample_clean.txt → exit $clean_exit (expected 0)"; ((FAIL++)) || true
fi

$SCD tests/sample_malicious.txt >/dev/null 2>&1
mal_exit=$?
if [ "$mal_exit" -eq 2 ]; then
    echo "  ✓ PASS: sample_malicious.txt → exit 2"; ((PASS++)) || true
else
    echo "  ✗ FAIL: sample_malicious.txt → exit $mal_exit (expected 2)"; ((FAIL++)) || true
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════"
[ "$FAIL" -eq 0 ] || exit 1
