+++
title = "mv"
chapter = false
weight = 100
hidden = false
+++

## Summary

Move or rename a file or directory.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### source

- Description: Source path
- Type: String
- Required: Required

#### destination

- Description: Destination path
- Type: String
- Required: Required

## Usage

```
mv {"source":"/tmp/implant","destination":"/usr/local/bin/update"}
```

## MITRE ATT&CK Mapping

- T1070.004

## Detailed Summary

Renames or moves a file or directory. On Linux and macOS this is an atomic rename when source and destination are on the same filesystem. Cross-filesystem moves may not be supported.
