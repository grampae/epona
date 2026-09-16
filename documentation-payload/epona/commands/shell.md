+++
title = "shell"
chapter = false
weight = 100
hidden = false
+++

## Summary

Run a command through the system shell.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### command

- Description: Command to run
- Type: String
- Required: Required

## Usage

```
shell {"command":"whoami /all"}
```
```
shell {"command":"uname -a"}
```

## MITRE ATT&CK Mapping

- T1059

## Detailed Summary

Executes the command via `/bin/sh -c` on Linux/macOS or `cmd.exe /c` on Windows. Both stdout and stderr are captured. If stdout is empty, stderr is returned. Prefer `run` for direct binary execution to reduce shell-based detection.
