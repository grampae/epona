+++
title = "netstat"
chapter = false
weight = 100
hidden = false
+++

## Summary

List active TCP connections without spawning a process.
- Needs Admin: False
- Supported OS: Linux
- Version: 1
- Author: @grampae

## Usage

```
netstat
```

## MITRE ATT&CK Mapping

- T1049

## Detailed Summary

Reads `/proc/net/tcp` and `/proc/net/tcp6` directly and decodes the hex-encoded addresses into human-readable `IP:port` pairs with connection state. No child process is spawned. Returns an error on non-Linux targets.
