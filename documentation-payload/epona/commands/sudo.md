+++
title = "sudo"
chapter = false
weight = 100
hidden = false
+++

## Summary

List commands the current user may run without a password via sudo.
- Needs Admin: False
- Supported OS: Linux, macOS
- Version: 1
- Author: @grampae

## Usage

```
sudo
```

## MITRE ATT&CK Mapping

- T1548.003

## Detailed Summary

Runs `sudo -n -l` to list allowed commands without prompting for a password. The `-n` flag prevents interactive prompts — if a password is required the command returns an error. Returns an error on Windows targets.
