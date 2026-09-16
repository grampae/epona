+++
title = "services"
chapter = false
weight = 100
hidden = false
+++

## Summary

Enumerate Win32 services via native API.
- Needs Admin: False
- Supported OS: Windows
- Version: 1
- Author: @grampae

## Usage

```
services
```

## MITRE ATT&CK Mapping

- T1007

## Detailed Summary

Uses `OpenSCManagerW` and `EnumServicesStatusExW` to enumerate all Win32 services, returning their name, PID, current state, and display name. No child process is spawned. Returns an error on non-Windows targets.
