+++
title = "sleep"
chapter = false
weight = 100
hidden = false
+++

## Summary

Update the agent's sleep interval and jitter percentage.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### seconds

- Description: Seconds between callbacks
- Type: Number
- Required: Required

#### jitter

- Description: Jitter percentage 0-100 — a random amount between 0 and jitter% of the interval is added to each sleep; there is also a small chance the sleep is doubled
- Type: Number
- Required: Optional
- Default Value: 0

## Usage

```
sleep {"seconds":60}
```
```
sleep {"seconds":300,"jitter":25}
```

## MITRE ATT&CK Mapping

None

## Detailed Summary

Sets the time between C2 callbacks. With jitter enabled, a random value between 0 and jitter% of the base interval is added to each sleep. Additionally, there is a small random chance the sleep is doubled. This is one-directional — the interval only increases, never decreases.
