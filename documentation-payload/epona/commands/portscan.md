+++
title = "portscan"
chapter = false
weight = 100
hidden = false
+++

## Summary

Concurrent native TCP port scanner running as a background job.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### hosts

- Description: Comma-separated IPs or CIDR ranges (e.g. 192.168.1.0/24,10.0.0.1)
- Type: String
- Required: Required

#### ports

- Description: Comma-separated ports or ranges (e.g. 22,80,443,8080-8090)
- Type: String
- Required: Optional
- Default Value: 22,80,443,445,3389,8080,8443

#### timeout

- Description: Per-connection timeout in milliseconds
- Type: Number
- Required: Optional
- Default Value: 1000

## Usage

```
portscan {"hosts":"192.168.1.0/24","ports":"22,80,443,3389"}
```
```
portscan {"hosts":"10.0.0.1,10.0.0.2","ports":"1-65535","timeout":500}
```

## MITRE ATT&CK Mapping

- T1046

## Detailed Summary

Performs TCP connect scans against each host/port combination using native non-blocking sockets. Runs as a background job — use `jobs` to check status and `jobkill` to cancel. Results are posted to Mythic when the scan completes. CIDR notation is supported; ranges larger than /16 (65536 hosts) are rejected. Port ranges are supported (e.g. `8000-9000`). This command can generate significant network noise.
