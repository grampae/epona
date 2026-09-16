+++
title = "mkdir"
chapter = false
weight = 100
hidden = false
+++

## Summary

Create a directory, including any missing intermediate directories.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### path

- Description: Directory path to create (intermediate directories are created as needed)
- Type: String
- Required: Required

## Usage

```
mkdir {"path":"/tmp/tools/output"}
```

## MITRE ATT&CK Mapping

- T1106

## Detailed Summary

Equivalent to `mkdir -p`. Creates all intermediate directories in the path. Returns success silently if the directory already exists.
