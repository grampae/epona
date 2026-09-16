+++
title = "launchctl"
chapter = false
weight = 100
hidden = false
+++

## Summary

List LaunchAgent and LaunchDaemon entries from user and system library directories.
- Needs Admin: False
- Supported OS: macOS
- Version: 1
- Author: @grampae

## Usage

```
launchctl
```

## MITRE ATT&CK Mapping

- T1543.004

## Detailed Summary

Reads plist filenames from `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/System/Library/LaunchDaemons`, and `/System/Library/LaunchAgents` without spawning the `launchctl` binary. Returns an error on non-macOS targets.
