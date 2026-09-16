+++
title = "getprivs"
chapter = false
weight = 100
hidden = false
+++

## Summary

List current process token privileges and their enabled/disabled state.
- Needs Admin: False
- Supported OS: Windows
- Version: 1
- Author: @grampae

## Usage

```
getprivs
```

## MITRE ATT&CK Mapping

- T1134

## Detailed Summary

Uses `OpenProcessToken`, `GetTokenInformation`, and `LookupPrivilegeNameW` to enumerate all privileges in the current process token without spawning a child process. Returns a table of privilege names and their current state (Enabled/Disabled). Returns an error on non-Windows targets.
