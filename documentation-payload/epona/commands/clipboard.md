+++
title = "clipboard"
chapter = false
weight = 100
hidden = false
+++

## Summary

Read the current contents of the Windows clipboard.
- Needs Admin: False
- Supported OS: Windows
- Version: 1
- Author: @grampae

## Usage

```
clipboard
```

## MITRE ATT&CK Mapping

- T1115

## Detailed Summary

Uses the native `OpenClipboard` / `GetClipboardData` API to read Unicode text from the clipboard without spawning a child process. Returns an error on non-Windows targets.
