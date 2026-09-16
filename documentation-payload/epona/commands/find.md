+++
title = "find"
chapter = false
weight = 100
hidden = false
+++

## Summary

Recursively search for files or directories by name pattern.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### path

- Description: Directory to search (default: current directory)
- Type: String
- Required: Optional
- Default Value: .

#### name

- Description: Filename pattern. Supports * wildcard: *.log, id_rsa, *secret*
- Type: String
- Required: Optional
- Default Value: 

#### kind

- Description: Entry type filter: 'f' for files, 'd' for directories, '' for both
- Type: String
- Required: Optional
- Default Value: 

#### maxdepth

- Description: Maximum recursion depth (-1 for unlimited)
- Type: Number
- Required: Optional
- Default Value: -1

## Usage

```
find {"path":"/home","name":"*.ssh","kind":"f"}
```
```
find {"path":"C:\\Users","name":"*.kdbx","maxdepth":5}
```
```
find {"path":"/etc","name":"*passwd*"}
```

## MITRE ATT&CK Mapping

- T1083

## Detailed Summary

Walks the directory tree from `path` and returns entries whose names match `name`. The wildcard `*` matches any sequence of characters. Results are capped at 10,000 entries. Errors accessing individual directories are silently skipped.
