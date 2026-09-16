<p align="center">
  <img src="documentation-payload/epona/epona.svg" width="280" alt="Epona" />
</p>

Epona is a cross-platform native agent written in Zig. It communicates over MQTT and HTTP, supports Mythic encryption, and compiles to a small, self-contained binary with no runtime dependencies.

## Installation

From the Mythic install directory, install from the public repository that hosts the release:

```
./mythic-cli install github https://github.com/grampae/epona
```

Once installed, restart Mythic to build a new agent.

## Notable Features

- Written in Zig 0.14 — compiles to a single self-contained binary with no runtime dependencies
- Cross-platform: Linux, macOS, and Windows from a single codebase
- Mythic encryption (AES-256-CBC + HMAC-SHA256 via Mythic's staging protocol)
- Dual C2 transport: MQTT or HTTP, selected at build time
- MQTT broker failover — up to 4 independently-encoded broker hostnames; agent tries each in order on failure, transparent to Mythic.  This is to allow the operator to employ MQTT bridges that forward traffic to and from the main MQTT C2 Profile broker.  When this is employed the main MQTT C2 Profile and Mythic C2 are not visible to the victim. See <a href="https://github.com/grampae/styx">styx</a>.
- Comptime ChaCha20 string obfuscation — per-string key+nonce derived from build salt; sensitive strings never appear in plaintext in the binary
- Per-build entropy — `build_salt` varies string ciphertext, junk blob size, section offsets, and code variants across every build
- Comptime code metamorphism — key functions compile to build-salt-selected instruction sequences so YARA rules don't match across builds
- AES-NI enforced at compile time on x86_64 — software AES T-tables stripped from the binary entirely
- Decoy strings — Go, Rust, C++/Qt, and IoT lookalike strings embedded to poison `strings(1)` output and automated language identification
- Anti-debug: PTRACE_TRACEME to block debugger attach; ptrace tracer detection at startup
- Linux sandbox detection: uptime and process-count heuristics; exits silently if triggered
- Kill timestamp — agent refuses to run after a configured date; value is encoded, not a plain integer in the binary
- MQTT port obfuscation — the port integer is XOR-encoded with a build-salt-derived key and stored in `.data`; decoded at runtime via a volatile pointer so the plain value never appears as an immediate in `.text`
- Section headers stripped from release binaries — `readelf -S`, `objdump -h`, and Ghidra auto-analysis degrade without the section header table
- Hash-based command dispatch — command names are never compared as strings at runtime
- AES keys, decryption keys, and session UUID scrambled in memory during sleep to defeat in-memory scanners
- Direct Windows syscalls via PEB walk — `NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtOpenProcess`, `NtCreateThreadEx` removed from the IAT entirely
- Native API preferred over spawning child processes (ps, netstat, getprivs, clipboard, services)
- Concurrent TCP port scanner running as a cancellable background job
- SOCKS5 proxy tunneled through Mythic
- Chunked file upload and download via Mythic's file transfer protocol
- Platform-specific commands for Windows, Linux, and macOS enumeration

## Commands Manual Quick Reference

Command | Syntax | Description | OS
------- | ------ | ----------- | --
cat | `cat {"path":"/etc/passwd"}` | Read and return the contents of a file. | All
cd | `cd {"path":"/tmp"}` | Change the agent's working directory. | All
clipboard | `clipboard` | Read the current contents of the clipboard. | Windows
cp | `cp {"source":"/tmp/a","destination":"/tmp/b"}` | Copy a file from source to destination. | All
cron | `cron` | Enumerate cron jobs from system and user crontabs. | Linux
download | `download {"path":"/etc/shadow"}` | Exfiltrate a file using Mythic's chunked transfer protocol. | All
env | `env` | Print all environment variables. | All
exit | `exit` | Terminate the agent process. | All
find | `find {"path":"/home","name":"*.ssh","kind":"f"}` | Recursively search for files or directories by name pattern. | All
getprivs | `getprivs` | List current process token privileges and enabled/disabled state. | Windows
jobkill | `jobkill {"id":1}` | Cancel a running background job by ID. | All
jobs | `jobs` | List all running background jobs. | All
kill | `kill {"pid":1234}` | Terminate a process by PID without spawning a shell. | Linux, macOS
launchctl | `launchctl` | List LaunchAgent and LaunchDaemon entries. | macOS
ls | `ls {"path":"/tmp"}` | List directory contents. | All
mkdir | `mkdir {"path":"/tmp/newdir"}` | Create a directory including any missing intermediate directories. | All
mv | `mv {"source":"/tmp/a","destination":"/tmp/b"}` | Move or rename a file or directory. | All
netstat | `netstat` | List active TCP connections via /proc/net/tcp without spawning a process. | Linux
osascript | `osascript {"code":"..."}` | Execute JavaScript for Automation (JXA) via osascript. | macOS
portscan | `portscan {"hosts":"192.168.1.0/24","ports":"22,80,443"}` | Concurrent native TCP port scanner running as a background job. | All
ps | `ps` | List running processes. | All
pwd | `pwd` | Print the current working directory. | All
rm | `rm {"path":"/tmp/file.txt"}` | Remove a file or directory. | All
run | `run {"executable":"/usr/bin/id"}` | Run a binary directly without a shell wrapper. | All
services | `services` | Enumerate Win32 services via native API. | Windows
shell | `shell {"command":"whoami"}` | Run a command through the system shell. | All
shinject | `shinject {"pid":1234,"shellcode":"<base64>"}` | Inject raw shellcode into a remote process via ptrace. | Linux x86_64
sleep | `sleep {"seconds":60,"jitter":20}` | Update the sleep interval and jitter percentage. | All
socks | `socks` | Enable the SOCKS5 relay — Mythic drives connection setup. | All
sudo | `sudo` | Run `sudo -n -l` to list passwordless sudo permissions. | Linux, macOS
upload | `upload {"file":"<file_id>","path":"/tmp/tool"}` | Upload a file to the target using Mythic's chunked transfer protocol. | All

## Supported C2 Profiles

### mqtt

Epona connects through MQTT bridge endpoints. Hostnames, port, topic, credentials, and TLS settings are set at build time.

Up to four bridge hostnames can be used (`mqtt_server_0` through `mqtt_server_3`). On each beacon cycle the agent tries them in order and falls back to the next on any connection or protocol error. Only `mqtt_server_0` is required; the rest default to empty and are skipped. Each hostname is encrypted independently with its own ChaCha20 key so a static analyst cannot correlate the fallback addresses. Configure fallback hosts through `mqtt_server_1`, `mqtt_server_2`, and `mqtt_server_3` when the MQTT C2 profile used for the operation exposes those optional parameters.

### http

Epona polls the Mythic HTTP C2 profile. Host, port, and URI are used at build time.
