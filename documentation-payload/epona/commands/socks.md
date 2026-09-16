+++
title = "socks"
chapter = false
weight = 100
hidden = false
+++

## Summary

Start or stop a SOCKS5 proxy tunneled through Mythic.
- Needs Admin: False
- Supported OS: Linux, macOS, Windows
- Version: 1
- Author: @grampae

### Arguments

#### action

- Description: start or stop the SOCKS5 proxy
- Type: ChooseOne
- Required: Optional
- Default Value: start

#### port

- Description: Local port for Mythic to listen on (0 = auto-assign)
- Type: Number
- Required: Optional
- Default Value: 0

## Usage

```
socks {"action":"start","port":1080}
```
```
socks {"action":"stop"}
```

## MITRE ATT&CK Mapping

- T1090

## Detailed Summary

Opens a SOCKS5 proxy tunnel through the Mythic C2 connection. Traffic is forwarded from Mythic's local listener through the agent to the target network. Runs as a background job — use `jobs` to confirm it is active and `jobkill` to stop it.
