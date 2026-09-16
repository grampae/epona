+++
title = "jobs"
chapter = false
weight = 100
hidden = false
+++

## Summary

List all running background jobs.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

## Usage

```
jobs
```

## MITRE ATT&CK Mapping

- T1057

## Detailed Summary

Returns a table of active background jobs showing the job ID, command name, and associated Mythic task ID. Background commands include `portscan` and `socks`. Use `jobkill` to cancel a job.
