+++
title = "cron"
chapter = false
weight = 100
hidden = false
+++

## Summary

Enumerate cron jobs from system and user crontabs.
- Needs Admin: False
- Supported OS: Linux
- Version: 1
- Author: @grampae

## Usage

```
cron
```

## MITRE ATT&CK Mapping

- T1053.003

## Detailed Summary

Reads `/etc/crontab`, all files under `/etc/cron.d/`, the periodic script directories (`/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`, `/etc/cron.monthly`), and user crontab files under `/var/spool/cron/crontabs/`. Also runs `crontab -l` for the current user. Returns an error on non-Linux targets.
