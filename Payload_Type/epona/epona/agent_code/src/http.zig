const std = @import("std");

fn dechunk(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var pos: usize = 0;
    while (pos < data.len) {
        const eol = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse break;
        const sz = std.fmt.parseInt(usize, std.mem.trim(u8, data[pos..eol], " \t"), 16) catch break;
        if (sz == 0) break;
        pos = eol + 2;
        if (pos + sz > data.len) break;
        try out.appendSlice(data[pos .. pos + sz]);
        pos += sz + 2;
    }
    return out.toOwnedSlice();
}

/// Minimal HTTP/1.1 POST client generic over any stream with read/writeAll methods.
/// Designed to work with mqtt.PlainStream and mqtt.TlsStream.
pub fn Client(comptime S: type) type {
    return struct {
        const Self = @This();
        stream: *S,

        pub fn init(stream: *S) Self {
            return .{ .stream = stream };
        }

        pub fn post(
            self:       *Self,
            allocator:  std.mem.Allocator,
            host:       []const u8,
            port:       u16,
            uri:        []const u8,
            user_agent: []const u8,
            body:       []const u8,
        ) ![]u8 {
            const req = try std.fmt.allocPrint(allocator,
                "POST /{s} HTTP/1.1\r\nHost: {s}:{d}\r\nUser-Agent: {s}\r\n" ++
                "Content-Type: application/octet-stream\r\nContent-Length: {d}\r\n" ++
                "Connection: close\r\n\r\n",
                .{ uri, host, port, user_agent, body.len },
            );
            defer allocator.free(req);
            try self.stream.writeAll(req);
            try self.stream.writeAll(body);

            // Read entire response — Connection: close means the server closes after sending
            var raw = std.ArrayList(u8).init(allocator);
            defer raw.deinit();
            var tmp: [8192]u8 = undefined;
            while (true) {
                const n = self.stream.read(&tmp) catch break;
                if (n == 0) break;
                try raw.appendSlice(tmp[0..n]);
            }

            const sep = std.mem.indexOf(u8, raw.items, "\r\n\r\n") orelse
                return error.InvalidHttpResponse;
            const hdr_slice  = raw.items[0..sep];
            const body_slice = raw.items[sep + 4..];

            var chunked = false;
            var line_it = std.mem.splitSequence(u8, hdr_slice, "\r\n");
            while (line_it.next()) |line| {
                const trimmed = std.mem.trim(u8, line, " \t");
                if (std.ascii.eqlIgnoreCase(trimmed, "transfer-encoding: chunked")) {
                    chunked = true;
                    break;
                }
            }

            return if (chunked)
                dechunk(allocator, body_slice)
            else
                allocator.dupe(u8, body_slice);
        }
    };
}
