+++
title = "ps"
chapter = false
weight = 100
hidden = false
+++

## Summary

List running processes.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

## Usage

```
ps
```

## MITRE ATT&CK Mapping

- T1057

## Detailed Summary

On Linux reads `/proc` directly for PID, PPID, owner UID, and command name. On Windows uses the Toolhelp32 API (`CreateToolhelp32Snapshot` / `Process32FirstW`). On macOS spawns `ps aux` to collect the process list. No child process is spawned on Linux or Windows.
