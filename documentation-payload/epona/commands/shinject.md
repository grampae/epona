+++
title = "shinject"
chapter = false
weight = 100
hidden = false
+++

## Summary

Inject raw shellcode into a remote process via ptrace.
- Needs Admin: False
- Supported OS: Linux
- Version: 1
- Author: @grampae

### Arguments

#### pid

- Description: Target process ID to inject shellcode into
- Type: Number
- Required: Required

#### shellcode

- Description: Raw shellcode file to inject
- Type: File
- Required: Required

## Usage

```
shinject {"pid":1234}
```

## MITRE ATT&CK Mapping

- T1055

## Detailed Summary

Attaches to the target process via `ptrace`, writes raw shellcode below the stack pointer (past the x86_64 red zone), redirects `RIP` to the shellcode, then detaches. The target process resumes execution of the injected code. Requires ptrace permissions on the target. Detectable via `PTRACE_ATTACH` events and `/proc/<pid>/status` `TracerPid` field. Linux x86_64 only.
