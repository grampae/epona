+++
title = "OPSEC"
chapter = false
weight = 10
pre = "<b>1. </b>"
+++

## Considerations

- Epona compiles to a stripped `ReleaseSmall` binary with debug info and symbol table removed. Sensitive configuration strings (C2 hostnames, topics, AES keys, file paths) are ChaCha20-obfuscated at compile time and decoded onto the stack at runtime — they do not appear in plaintext in the binary.
- Every decoded string buffer is zeroed with `@memset` immediately after use so plaintext does not linger on the stack.
- On Linux, sandbox detection runs at startup: if system uptime is under 5 minutes or fewer than 50 processes are running, the agent exits cleanly.
- A kill timestamp is baked in at build time. The agent checks the current time on each callback and exits cleanly if the timestamp has passed.
- A random 64-bit build salt is generated per payload so two builds with identical config still produce different binaries on disk.
- The binary stack size is set to 8 MB (vs. Zig's 16 MB default), reducing a well-known Zig runtime fingerprint in PE/ELF headers.
- Position-Independent Executable (PIE) is enabled so ASLR randomizes the load address on every execution.
- The `.comment` ELF section (which contains the Zig/LLD version string) is discarded at link time.

### Commands That Spawn Child Processes

The following commands spawn a child process and are more detectable than native API alternatives:

- `shell` — spawns `/bin/sh -c` (Linux/macOS) or `cmd.exe /c` (Windows).
- `run` — spawns the specified binary directly.
- `sudo` — spawns `sudo -n -l`.
- `cron` — spawns `crontab -l` for the current user in addition to reading files.
- `osascript` — spawns `osascript -l JavaScript -e <code>`.
- `ps` (macOS only) — spawns `ps aux`; macOS has no `/proc` filesystem.

### Commands That Use Native APIs (No Child Process)

- `ps` (Linux) — reads `/proc` directly for PID, PPID, owner UID, and command name.
- `ps` (Windows) — uses Toolhelp32 (`CreateToolhelp32Snapshot` / `Process32FirstW`).
- `netstat` — reads `/proc/net/tcp` and `/proc/net/tcp6` directly.
- `getprivs` — uses `OpenProcessToken` / `GetTokenInformation` / `LookupPrivilegeNameW`.
- `clipboard` — uses `OpenClipboard` / `GetClipboardData`.
- `services` — uses `OpenSCManagerW` / `EnumServicesStatusExW`.
- `launchctl` — reads LaunchAgent/Daemon plist directories without spawning `launchctl`.

### Sleep Obfuscation

During each sleep interval, the agent generates a fresh 32-byte ephemeral random key, XORs both the AES encryption and decryption keys in place, then sleeps. The keys are restored by XORing again with the same key immediately after waking. The ephemeral key is zeroed before returning. Memory scanners that scan the process during sleep will find garbage where the AES material lives.

### Anti-Debug (Linux)

On Linux, the agent calls `ptrace(PTRACE_TRACEME, ...)` during initialization. If a debugger is already attached, the kernel returns a non-zero error and the agent exits silently before performing any network activity.

### Direct Windows Syscalls

The following NT functions are invoked via the `syscall` instruction directly rather than through ntdll stubs:

- `NtProtectVirtualMemory`
- `NtAllocateVirtualMemory`
- `NtWriteVirtualMemory`
- `NtOpenProcess`
- `NtCreateThreadEx`

At startup, the agent walks the PEB (`gs:0x60`) to locate ntdll without calling `GetModuleHandle`, parses the export directory, and resolves each function's Syscall Service Number (SSN) by counting Nt\* stubs with a lower RVA. This approach is immune to inline hooks because it uses address ordering rather than reading the stub bytes. None of these functions appear in the PE import table.

### MQTT Port Obfuscation

The MQTT port integer (e.g. 8883) is XOR-encoded at compile time using a pair of bytes derived from the build salt and stored in a `.data` global. At runtime, `mqttPort()` reads the two bytes through a `*volatile [2]u8` pointer (preventing the optimizer from constant-folding through the read) and XORs them back to recover the original value. The plain port integer never appears as an immediate operand in `.text`. Because the XOR key changes with every payload, the encoded bytes differ across builds even when the port is the same.

### macOS Mach-O Symbol Stripping

Zig's comptime string obfuscation stores encrypted ciphertext in the binary, but the Zig compiler names every anonymous comptime-generated struct after the source expression that created it (e.g. `Enc("mqtt.example.com")`). On Mach-O, `-fstrip` removes debug sections but leaves the local symbol table intact — exposing every plaintext string that was ever passed to the `Enc()` macro as a symbol name.

The post-build step attempts `llvm-strip -x` on macOS binaries to remove all non-global (local) symbols, eliminating these names while preserving the external symbols that the macOS dynamic linker requires. The builder Dockerfile installs LLVM, which provides `llvm-strip`.

### shinject (Linux)

`shinject` attaches to a remote process via `ptrace`, writes shellcode into the process's stack below the red zone, and redirects `RIP`. Ptrace-based injection is detectable by security tools monitoring `PTRACE_ATTACH` events and by the `TracerPid` field in `/proc/<pid>/status`.

### Network

- `portscan` makes direct TCP connection attempts to each host/port pair and can generate significant network noise. It runs as a cancellable background job.
- `socks` opens an outbound tunnel to Mythic for SOCKS5 proxying. Traffic originates from the agent host.
- All C2 traffic is encrypted by the Mythic framework (AES-256-CBC with HMAC-SHA256 integrity). Key exchange is handled by Mythic's staging protocol.

### Windows Import Table

Windows builds load sensitive Win32 APIs dynamically at runtime via `LoadLibraryW` + `GetProcAddress`. The function name strings are XOR-encoded and decoded to the stack immediately before use. As a result:

- `advapi32.dll` does not appear as a static import for privilege or service enumeration functions (`OpenProcessToken`, `LookupPrivilegeNameW`, `GetTokenInformation`, `OpenSCManagerW`, `EnumServicesStatusExW`, `CloseServiceHandle`).
- `user32.dll` does not appear as a static import at all (`OpenClipboard`, `CloseClipboard`, `GetClipboardData`).
- The five NT functions listed under Direct Windows Syscalls do not appear in the import table.

The remaining ntdll imports are Zig stdlib file I/O functions (`NtCreateFile`, `NtClose`, etc.) which are necessary for cross-platform filesystem operations and cannot be easily removed without replacing the stdlib.
