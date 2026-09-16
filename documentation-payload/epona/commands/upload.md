+++
title = "upload"
chapter = false
weight = 100
hidden = false
+++

## Summary

Upload a file to the target using Mythic's chunked file transfer protocol.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### file

- Description: File to upload from the operator's machine
- Type: File
- Required: Required

#### path

- Description: Absolute destination path on the target
- Type: String
- Required: Required

## Usage

```
upload {"path":"/tmp/linpeas.sh"}
```

## MITRE ATT&CK Mapping

- T1105

## Detailed Summary

Receives the file from Mythic in 512 KB chunks and writes it to the specified destination path on the target. The destination file is truncated and overwritten if it already exists.
