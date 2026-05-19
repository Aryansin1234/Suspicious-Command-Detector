#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# SCD — Suspicious Command Detector
# Startup script with animated intro
# ─────────────────────────────────────────────────────────────────

# Colors
R="\033[1;31m"
O="\033[38;5;208m"
Y="\033[1;33m"
G="\033[1;32m"
C="\033[1;36m"
B="\033[1;34m"
W="\033[1;37m"
D="\033[2m"
RST="\033[0m"

clear

# Typing effect
type_text() {
    local text="$1"
    local delay="${2:-0.03}"
    for ((i=0; i<${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

# Slow print
slow_print() {
    echo -e "$1"
    sleep "${2:-0.3}"
}

# ─── ASCII Art Logo ──────────────────────────────────────────────

echo ""
sleep 0.3
slow_print "${R}    ███████╗ ██████╗██████╗ " 0.1
slow_print "${O}    ██╔════╝██╔════╝██╔══██╗" 0.1
slow_print "${Y}    ███████╗██║     ██║  ██║" 0.1
slow_print "${G}    ╚════██║██║     ██║  ██║" 0.1
slow_print "${C}    ███████║╚██████╗██████╔╝" 0.1
slow_print "${B}    ╚══════╝ ╚═════╝╚═════╝ " 0.1
echo ""
slow_print "${W}    Suspicious Command Detector${RST}" 0.5

# ─── Tagline ─────────────────────────────────────────────────────

echo ""
type_text "    $(echo -e "${D}\"Your last line of defense before a dangerous command runs.\"${RST}")" 0.04
echo ""
sleep 0.5

# ─── System Info ─────────────────────────────────────────────────

slow_print "${C}    ┌──────────────────────────────────────────┐${RST}" 0.1
slow_print "${C}    │${RST}  ${W}System Programming Project${RST}               ${C}│${RST}" 0.1
slow_print "${C}    │${RST}                                          ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${G}►${RST} Process Control  : fork, exec, wait   ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${G}►${RST} IPC              : pipe()             ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${G}►${RST} Signal Handling  : SIGINT             ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${G}►${RST} POSIX Regex      : regcomp/regexec    ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${G}►${RST} File I/O         : Rule config loader ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${G}►${RST} Shell Parsing    : Tokenizer engine   ${C}│${RST}" 0.1
slow_print "${C}    │${RST}                                          ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${D}113 detection rules | Score 0-100${RST}       ${C}│${RST}" 0.1
slow_print "${C}    │${RST}  ${D}Runs in isolated Docker container${RST}       ${C}│${RST}" 0.1
slow_print "${C}    └──────────────────────────────────────────┘${RST}" 0.1
echo ""
sleep 0.3

# ─── How it works ────────────────────────────────────────────────

slow_print "${Y}    How it works:${RST}" 0.2
slow_print "${D}    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐${RST}" 0.1
slow_print "${D}    │  Input  │───▶│  Parse  │───▶│  Match  │───▶│  Score  │${RST}" 0.1
slow_print "${D}    │ Command │    │ Tokenize│    │  Rules  │    │  0-100  │${RST}" 0.1
slow_print "${D}    └─────────┘    └─────────┘    └─────────┘    └────┬────┘${RST}" 0.1
slow_print "${D}                                                      │${RST}" 0.1
slow_print "${D}                                          ┌───────────┴───────────┐${RST}" 0.1
slow_print "${D}                                          │                       │${RST}" 0.1
slow_print "${D}                                     ${G}Score < 20${RST}${D}           ${R}Score ≥ 20${RST}" 0.1
slow_print "${D}                                     ${G}✓ Execute${RST}${D}            ${R}⚠ Warn + Ask${RST}" 0.1
echo ""
sleep 0.5

# ─── Press Enter ─────────────────────────────────────────────────

echo ""
echo -ne "${W}    Press ENTER to launch SCD Guard Shell...${RST}"
read -r
echo ""
slow_print "${G}    ⚡ Launching...${RST}" 0.3
sleep 0.5
clear

# ─── Launch SCD ──────────────────────────────────────────────────

exec ./scd
