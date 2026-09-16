+++
title = "rm"
chapter = false
weight = 100
hidden = false
+++

## Summary

Remove a file or directory.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### path

- Description: File or directory path to remove (or the directory when -file is used)
- Type: String
- Required: Required

#### file

- Description: Filename to remove — when provided, path is treated as the parent directory
- Type: String
- Required: Optional
- Default Value: 

## Usage

```
rm {"path":"/tmp/artifact.bin"}
```
```
rm {"path":"/tmp","file":"artifact.bin"}
```

## MITRE ATT&CK Mapping

- T1070.004

## Detailed Summary

Attempts to delete the target as a file first, then as an empty directory. Non-empty directories are not recursively deleted.
