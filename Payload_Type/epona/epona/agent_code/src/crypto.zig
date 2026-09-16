// Mythic aes256_hmac crypto:
//   encrypt(key, plaintext) -> IV[16] | AES256_CBC(padded) | HMAC_SHA256(IV|CT)
//   decrypt(key, data)      -> plaintext  (data = IV[16] | CT | HMAC[32])
//   wire format             -> base64(UUID[36] | encrypt(json))

const std    = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;
const Hmac   = std.crypto.auth.hmac.sha2.HmacSha256;

const BLOCK = 16;
const HMAC_LEN = Hmac.mac_length; // 32

// PKCS#7 pad to block boundary, always adds 1–16 bytes
fn pkcs7Len(plaintext_len: usize) usize {
    const pad = BLOCK - (plaintext_len % BLOCK);
    return plaintext_len + pad;
}

fn pkcs7Pad(dst: []u8, plaintext: []const u8) void {
    const pad: u8 = @intCast(BLOCK - (plaintext.len % BLOCK));
    @memcpy(dst[0..plaintext.len], plaintext);
    @memset(dst[plaintext.len..], pad);
}

fn pkcs7Unpad(data: []const u8) ![]const u8 {
    if (data.len == 0 or data.len % BLOCK != 0) return error.BadPadding;
    const pad = data[data.len - 1];
    if (pad == 0 or pad > BLOCK) return error.BadPadding;
    for (data[data.len - pad ..]) |b| {
        if (b != pad) return error.BadPadding;
    }
    return data[0 .. data.len - pad];
}

fn cbcEncrypt(key: [32]u8, iv: [BLOCK]u8, padded: []u8) void {
    const ctx = Aes256.initEnc(key);
    var prev  = iv;
    var i: usize = 0;
    while (i < padded.len) : (i += BLOCK) {
        const block = padded[i..][0..BLOCK];
        for (block, 0..) |*b, j| b.* ^= prev[j];
        var out: [BLOCK]u8 = undefined;
        ctx.encrypt(&out, block[0..BLOCK]);
        @memcpy(block, &out);
        prev = out;
    }
}

fn cbcDecrypt(key: [32]u8, iv: [BLOCK]u8, ct: []u8) void {
    const ctx = Aes256.initDec(key);
    var prev  = iv;
    var i: usize = 0;
    while (i < ct.len) : (i += BLOCK) {
        const block = ct[i..][0..BLOCK];
        var pt: [BLOCK]u8 = undefined;
        ctx.decrypt(&pt, block[0..BLOCK]);
        for (&pt, 0..) |*b, j| b.* ^= prev[j];
        prev = block.*;
        @memcpy(block, &pt);
    }
}

// Decode base64 key → 32 raw bytes
pub fn decodeKey(b64: []const u8) ![32]u8 {
    var raw: [32]u8 = undefined;
    const n = try std.base64.standard.Decoder.calcSizeForSlice(b64);
    if (n != 32) return error.InvalidKeyLength;
    try std.base64.standard.Decoder.decode(&raw, b64);
    return raw;
}

// encrypt: returns  IV[16] | CT | HMAC[32]   (caller frees)
pub fn encrypt(allocator: std.mem.Allocator, key: [32]u8, plaintext: []const u8) ![]u8 {
    const padded_len = pkcs7Len(plaintext.len);
    const out_len    = BLOCK + padded_len + HMAC_LEN;
    const out        = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var iv: [BLOCK]u8 = undefined;
    std.crypto.random.bytes(&iv);
    @memcpy(out[0..BLOCK], &iv);

    const ct = out[BLOCK .. BLOCK + padded_len];
    pkcs7Pad(ct, plaintext);
    cbcEncrypt(key, iv, ct);

    var mac: [HMAC_LEN]u8 = undefined;
    Hmac.create(&mac, out[0 .. BLOCK + padded_len], &key);
    @memcpy(out[BLOCK + padded_len ..], &mac);

    return out;
}

// decrypt: input = IV[16] | CT | HMAC[32], returns plaintext (caller frees)
pub fn decrypt(allocator: std.mem.Allocator, key: [32]u8, data: []const u8) ![]u8 {
    if (data.len < BLOCK + BLOCK + HMAC_LEN) return error.DataTooShort;

    const iv    = data[0..BLOCK].*;
    const ct    = data[BLOCK .. data.len - HMAC_LEN];
    const mac   = data[data.len - HMAC_LEN ..];

    // Verify HMAC
    var expected: [HMAC_LEN]u8 = undefined;
    Hmac.create(&expected, data[0 .. data.len - HMAC_LEN], &key);
    if (!std.crypto.timing_safe.eql([HMAC_LEN]u8, expected, mac[0..HMAC_LEN].*))
        return error.HmacMismatch;

    // Decrypt in place on a copy
    const ct_copy = try allocator.dupe(u8, ct);
    defer allocator.free(ct_copy);
    cbcDecrypt(key, iv, ct_copy);

    const plaintext = try pkcs7Unpad(ct_copy);
    return allocator.dupe(u8, plaintext);
}
