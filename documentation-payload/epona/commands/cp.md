+++
title = "cp"
chapter = false
weight = 100
hidden = false
+++

## Summary

Copy a file from source to destination.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### source

- Description: Source file path
- Type: String
- Required: Required

#### destination

- Description: Destination file path
- Type: String
- Required: Required

## Usage

```
cp {"source":"/tmp/original","destination":"/tmp/copy"}
```

## MITRE ATT&CK Mapping

- T1005

## Detailed Summary

Copies a single file. Destination directories must already exist. Does not support recursive directory copies.
