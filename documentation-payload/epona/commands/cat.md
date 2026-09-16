+++
title = "cat"
chapter = false
weight = 100
hidden = false
+++

## Summary

Read and return the contents of a file.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### path

- Description: File to read
- Type: String
- Required: Required

## Usage

```
cat {"path":"/etc/passwd"}
```

## MITRE ATT&CK Mapping

- T1005

## Detailed Summary

Opens the specified file and returns its full contents. Binary files are returned as-is. There is no size limit enforced by the command itself beyond available memory.
