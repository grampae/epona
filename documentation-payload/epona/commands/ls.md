+++
title = "ls"
chapter = false
weight = 100
hidden = false
+++

## Summary

List directory contents.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### path

- Description: Directory to list (default: current directory)
- Type: String
- Required: Optional
- Default Value: .

## Usage

```
ls
```
```
ls {"path":"/etc"}
```
```
ls {"path":"C:\\Windows\\System32"}
```

## MITRE ATT&CK Mapping

- T1083

## Detailed Summary

Returns one entry per line for all files and directories in the specified path. Does not recurse — use `find` for recursive searches.
