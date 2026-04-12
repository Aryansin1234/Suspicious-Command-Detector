# 🛡️ SCD eBPF Integration

This directory contains experimental eBPF scripts designed to integrate with the Suspicious Command Detector (SCD) at the kernel level.

## Why eBPF?

Normally, SCD relies on shell history files (`.bash_history`, `syslog`, etc.) to analyze user activity. This has a limitation: attackers can manipulate or bypass the shell history (e.g., configuring `HISTFILE=/dev/null` or prepending commands with spaces).

Using **eBPF (Extended Berkeley Packet Filter)**, we can trace commands directly at the Linux kernel level during the `execve` syscall. This makes it impossible for an attacker to hide their executed commands by manipulating user-space logs.

## Available Hooks

### `scd_execve.bt`
A [bpftrace](https://github.com/iovisor/bpftrace) script that hooks into the `sys_enter_execve` tracepoint and outputs every executed command string.

#### Usage

You must run the bpftrace hook as root (it requires kernel tracing capabilities), but you can pipe its output directly into `scd`.

```bash
# Ensure bpftrace is installed
sudo apt install bpftrace  # Ubuntu/Debian
sudo dnf install bpftrace  # Fedora/RHEL

# Run the hook and pipe it to SCD
sudo ./ebpf/scd_execve.bt | ./scd -v
```

Now, no matter how the user tries to hide their tracks (e.g., unsetting `HISTFILE`), the actual kernel execution is intercepted, logged by bpftrace, and instantly scored by SCD!
