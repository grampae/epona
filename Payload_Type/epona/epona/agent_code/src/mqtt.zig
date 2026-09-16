const std = @import("std");

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

fn writeRemLen(writer: anytype, length: u32) !void {
    var l = length;
    while (true) {
        var byte: u8 = @intCast(l & 0x7F);
        l >>= 7;
        if (l > 0) byte |= 0x80;
        try writer.writeByte(byte);
        if (l == 0) break;
    }
}

fn readRemLen(reader: anytype) !u32 {
    var result: u32 = 0;
    var shift: u5 = 0;
    for (0..4) |_| {
        const byte = try reader.readByte();
        result |= @as(u32, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) return result;
        shift +|= 7;
    }
    return error.MalformedPacket;
}

fn writeMqttStr(writer: anytype, s: []const u8) !void {
    const hi: u8 = @intCast((s.len >> 8) & 0xFF);
    const lo: u8 = @intCast(s.len & 0xFF);
    try writer.writeByte(hi);
    try writer.writeByte(lo);
    try writer.writeAll(s);
}

// ---------------------------------------------------------------------------
// Plain TCP stream wrapper (implements read/writeAll/close)
// ---------------------------------------------------------------------------

pub const PlainStream = struct {
    inner: std.net.Stream,

    pub fn read(self: *PlainStream, buf: []u8) !usize {
        return self.inner.read(buf);
    }

    pub fn writeAll(self: *PlainStream, data: []const u8) !void {
        return self.inner.writeAll(data);
    }

    pub fn close(self: *PlainStream) void {
        self.inner.close();
    }
};

// ---------------------------------------------------------------------------
// TLS stream wrapper
// ---------------------------------------------------------------------------

pub const TlsStream = struct {
    tls:    std.crypto.tls.Client,
    stream: std.net.Stream,

    pub fn read(self: *TlsStream, buf: []u8) !usize {
        return self.tls.read(self.stream, buf);
    }

    pub fn writeAll(self: *TlsStream, data: []const u8) !void {
        try self.tls.writeAll(self.stream, data);
    }

    pub fn close(self: *TlsStream) void {
        self.tls.writeAllEnd(self.stream, &.{}, true) catch {};
        self.stream.close();
    }
};

// ---------------------------------------------------------------------------
// Generic MQTT 3.1.1 client (QoS 0, minimal subset)
// ---------------------------------------------------------------------------

pub fn Client(comptime S: type) type {
    return struct {
        const Self = @This();
        stream: *S,
        read_buf: [4096]u8 = undefined,

        pub fn init(stream: *S) Self {
            return .{ .stream = stream };
        }

        // ------------------------------------------------------------------
        // Internal read helpers (guaranteed full reads)
        // ------------------------------------------------------------------

        fn readByte(self: *Self) !u8 {
            var b: [1]u8 = undefined;
            var off: usize = 0;
            while (off < 1) {
                const n = try self.stream.read(b[off..]);
                if (n == 0) return error.ConnectionClosed;
                off += n;
            }
            return b[0];
        }

        fn readExact(self: *Self, buf: []u8) !void {
            var off: usize = 0;
            while (off < buf.len) {
                const n = try self.stream.read(buf[off..]);
                if (n == 0) return error.ConnectionClosed;
                off += n;
            }
        }

        fn skipBytes(self: *Self, count: u32) !void {
            var remaining = count;
            while (remaining > 0) {
                const chunk = @min(remaining, self.read_buf.len);
                try self.readExact(self.read_buf[0..chunk]);
                remaining -= @intCast(chunk);
            }
        }

        // ------------------------------------------------------------------
        // CONNECT
        // ------------------------------------------------------------------

        pub fn connect(
            self:      *Self,
            client_id: []const u8,
            user:      []const u8,
            pass:      []const u8,
        ) !void {
            // Calculate remaining length
            var rem: u32 = 10; // protocol name (6) + level (1) + flags (1) + keepalive (2)
            rem += 2 + @as(u32, @intCast(client_id.len));
            if (user.len > 0) rem += 2 + @as(u32, @intCast(user.len));
            if (pass.len > 0) rem += 2 + @as(u32, @intCast(pass.len));

            // Build packet in a local buffer to do a single write
            var pkt: [512]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&pkt);
            const w = fbs.writer();

            try w.writeByte(0x10); // CONNECT
            try writeRemLen(w, rem);
            try w.writeAll("\x00\x04MQTT"); // Protocol name
            try w.writeByte(0x04);           // Protocol level 3.1.1
            var flags: u8 = 0x02;            // Clean session
            if (user.len > 0) flags |= 0x80;
            if (pass.len > 0) flags |= 0x40;
            try w.writeByte(flags);
            try w.writeAll("\x00\x3C");      // Keep-alive 60s
            try writeMqttStr(w, client_id);
            if (user.len > 0) try writeMqttStr(w, user);
            if (pass.len > 0) try writeMqttStr(w, pass);

            try self.stream.writeAll(pkt[0..fbs.pos]);

            // Read CONNACK
            if (try self.readByte() != 0x20) return error.UnexpectedPacket;
            if (try self.readRemLen() != 2)  return error.UnexpectedPacket;
            _ = try self.readByte(); // session present flag
            if (try self.readByte() != 0x00) return error.ConnectRefused;
        }

        fn readRemLen(self: *Self) !u32 {
            var result: u32 = 0;
            var shift: u5 = 0;
            for (0..4) |_| {
                const byte = try self.readByte();
                result |= @as(u32, byte & 0x7F) << shift;
                if (byte & 0x80 == 0) return result;
                shift +|= 7;
            }
            return error.MalformedPacket;
        }

        // ------------------------------------------------------------------
        // SUBSCRIBE (QoS 0, packet ID = 1)
        // ------------------------------------------------------------------

        pub fn subscribe(self: *Self, topic: []const u8) !void {
            // rem = 2 (pkt_id) + 2 (topic_len) + topic.len + 1 (qos)
            const rem: u32 = @intCast(5 + topic.len);

            var pkt: [512]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&pkt);
            const w = fbs.writer();

            try w.writeByte(0x82);        // SUBSCRIBE
            try writeRemLen(w, rem);
            try w.writeAll("\x00\x01");   // Packet ID = 1
            try writeMqttStr(w, topic);
            try w.writeByte(0x00);        // QoS 0

            try self.stream.writeAll(pkt[0..fbs.pos]);

            // Read SUBACK
            if (try self.readByte() != 0x90) return error.UnexpectedPacket;
            const suback_rem = try self.readRemLen();
            if (suback_rem < 3) return error.UnexpectedPacket;
            _ = try self.readByte(); // pkt id hi
            _ = try self.readByte(); // pkt id lo
            const rc = try self.readByte();
            if (rc == 0x80) return error.SubscribeFailed;
            // Skip any extra bytes
            if (suback_rem > 3) try self.skipBytes(suback_rem - 3);
        }

        // ------------------------------------------------------------------
        // PUBLISH (QoS 0 – fire and forget, no response expected)
        // ------------------------------------------------------------------

        pub fn publish(self: *Self, topic: []const u8, payload: []const u8) !void {
            // rem = 2 (topic_len) + topic.len + payload.len
            const rem: u32 = @intCast(2 + topic.len + payload.len);

            var hdr: [6]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&hdr);
            const w = fbs.writer();
            try w.writeByte(0x30); // PUBLISH QoS 0
            try writeRemLen(w, rem);
            const hi: u8 = @intCast((topic.len >> 8) & 0xFF);
            const lo: u8 = @intCast(topic.len & 0xFF);
            try w.writeByte(hi);
            try w.writeByte(lo);

            try self.stream.writeAll(hdr[0..fbs.pos]);
            try self.stream.writeAll(topic);
            try self.stream.writeAll(payload);
        }

        // ------------------------------------------------------------------
        // Wait for an inbound PUBLISH and return its payload (caller frees)
        // ------------------------------------------------------------------

        pub fn waitForPublish(self: *Self, allocator: std.mem.Allocator) ![]u8 {
            while (true) {
                const pkt_byte = try self.readByte();
                const rem      = try self.readRemLen();

                switch (pkt_byte & 0xF0) {
                    0x30 => { // PUBLISH
                        // Topic length
                        var tl_hi: [1]u8 = undefined;
                        var tl_lo: [1]u8 = undefined;
                        try self.readExact(&tl_hi);
                        try self.readExact(&tl_lo);
                        const topic_len = @as(u32, tl_hi[0]) << 8 | tl_lo[0];
                        // Skip topic
                        try self.skipBytes(topic_len);
                        // Packet ID only for QoS 1/2
                        const qos = (pkt_byte >> 1) & 0x03;
                        const hdr_extra: u32 = if (qos > 0) 2 else 0;
                        if (qos > 0) try self.skipBytes(2);
                        // Payload
                        const payload_len = rem - 2 - topic_len - hdr_extra;
                        const payload = try allocator.alloc(u8, payload_len);
                        errdefer allocator.free(payload);
                        try self.readExact(payload);
                        return payload;
                    },
                    0xD0 => try self.skipBytes(rem), // PINGRESP
                    else  => try self.skipBytes(rem), // ignore unknown
                }
            }
        }

        // ------------------------------------------------------------------
        // DISCONNECT
        // ------------------------------------------------------------------

        pub fn disconnect(self: *Self) !void {
            try self.stream.writeAll("\xE0\x00");
        }
    };
}
