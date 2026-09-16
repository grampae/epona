+++
title = "cd"
chapter = false
weight = 100
hidden = false
+++

## Summary

Change the agent's working directory.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### path

- Description: Directory to change to
- Type: String
- Required: Required

## Usage

```
cd {"path":"/tmp"}
```
```
cd {"path":"C:\\Users\\Public"}
```

## MITRE ATT&CK Mapping

None

## Detailed Summary

Updates the agent's current working directory. Relative paths in subsequent commands such as `ls` and `cat` resolve from this location.
