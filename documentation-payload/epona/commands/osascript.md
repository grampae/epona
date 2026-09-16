+++
title = "osascript"
chapter = false
weight = 100
hidden = false
+++

## Summary

Execute JavaScript for Automation (JXA) via osascript.
- Needs Admin: False
- Supported OS: macOS
- Version: 1
- Author: @grampae

### Arguments

#### code

- Description: JavaScript for Automation (JXA) code to execute
- Type: String
- Required: Required

## Usage

```
osascript {"code":"Application('Terminal').doScript('whoami')"}
```
```
osascript {"code":"Application('System Events').currentUser().name()"}
```

## MITRE ATT&CK Mapping

- T1059.002

## Detailed Summary

Runs the provided JXA code via `osascript -l JavaScript -e <code>`. JXA has broad system scripting access including application control, file system operations, and user interface automation. Returns an error on non-macOS targets.
