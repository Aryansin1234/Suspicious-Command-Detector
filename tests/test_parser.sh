#!/bin/bash
# test_parser.sh — Parser & tokenization tests
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SCD=./scd

assert_flag() {
    local desc="$1" input="$2" expected="$3"
    local actual
    actual=$(echo "$input" | $SCD -v 2>&1) || true
    if echo "$actual" | grep -qi "$expected"; then
        echo "  ✓ PASS: $desc"; ((PASS++)) || true
    else
        echo "  ✗ FAIL: $desc"
        echo "    expected to find: $expected"
        echo "    got: $actual"
        ((FAIL++)) || true
    fi
}

assert_clean() {
    local desc="$1" input="$2"
    local actual
    actual=$(echo "$input" | $SCD -v 2>&1) || true
    if echo "$actual" | grep -q "CLEAN"; then
        echo "  ✓ PASS: $desc"; ((PASS++)) || true || true
    else
        echo "  ✗ FAIL: $desc (expected CLEAN)"
        echo "    got: $actual"
        ((FAIL++)) || true || true
    fi
}

assert_score_label() {
    local desc="$1" input="$2" label="$3"
    local actual
    actual=$(echo "$input" | $SCD -v 2>&1) || true
    if echo "$actual" | grep -qi "$label"; then
        echo "  ✓ PASS: $desc"; ((PASS++)) || true || true
    else
        echo "  ✗ FAIL: $desc (expected $label)"
        echo "    got: $actual"
        ((FAIL++)) || true || true
    fi
}

echo "═══════════════════════════════════════════"
echo " SCD Parser Tests"
echo "═══════════════════════════════════════════"

# Basic clean commands
assert_clean "Simple ls"       "ls -la /home"
assert_clean "pwd command"     "pwd"
assert_clean "echo hello"      "echo hello world"
assert_clean "mkdir"           "mkdir -p /tmp/testdir"
assert_clean "cat file"        "cat /tmp/file.txt"
assert_clean "grep pattern"    "grep -r 'main' src/"

# Commands with pipes (clean)
assert_clean "grep pipe"       "cat file.txt | grep pattern"
assert_clean "sort pipe"       "ls -la | sort -k5"

# Empty and comment lines (should pass through cleanly with score 0)
assert_score_label "Empty line"      ""                      "clean"
assert_score_label "Comment line"    "# this is a comment"   "clean"

echo ""
echo "Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════"
[ "$FAIL" -eq 0 ] || exit 1
