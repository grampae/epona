+++
title = "kill"
chapter = false
weight = 100
hidden = false
+++

## Summary

Terminate a process by PID without spawning a shell.
- Needs Admin: False
- Supported OS: Linux, macOS
- Version: 1
- Author: @grampae

### Arguments

#### pid

- Description: Process ID to terminate
- Type: Number
- Required: Required

## Usage

```
kill {"pid":1234}
```

## MITRE ATT&CK Mapping

- T1106

## Detailed Summary

Sends `SIGKILL` to the specified PID via the `kill` syscall directly. No child process is spawned. Returns an error on Windows targets.
