+++
title = "run"
chapter = false
weight = 100
hidden = false
+++

## Summary

Run a binary directly without a shell wrapper.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### executable

- Description: Binary to execute
- Type: String
- Required: Required

#### arguments

- Description: Space-separated arguments to pass to the binary
- Type: String
- Required: Optional
- Default Value: 

## Usage

```
run {"executable":"/usr/bin/id"}
```
```
run {"executable":"net.exe","arguments":"localgroup administrators"}
```

## MITRE ATT&CK Mapping

- T1106

## Detailed Summary

Spawns the specified binary with arguments split on spaces. Unlike `shell`, no shell interpreter is involved, which reduces detection surface. stdout and stderr are captured and returned. If stdout is empty, stderr is returned instead.
