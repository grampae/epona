+++
title = "jobkill"
chapter = false
weight = 100
hidden = false
+++

## Summary

Cancel a running background job by its ID.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### id

- Description: Job ID to cancel (from 'jobs' output)
- Type: Number
- Required: Required

## Usage

```
jobkill {"id":1}
```

## MITRE ATT&CK Mapping

- T1057

## Detailed Summary

Sets the cancellation flag for the specified job. The job thread checks this flag and exits cleanly at the next opportunity. Use `jobs` to list active job IDs.
