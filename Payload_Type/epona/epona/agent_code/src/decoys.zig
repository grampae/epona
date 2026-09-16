// Decoy strings — plaintext strings embedded in .rodata to flood strings(1)
// output and poison automated language-identification.
//
// An analyst's first step is "strings binary | grep -i <keyword>".  Mixing
// Go runtime artifacts, Rust panic strings, C++/Qt symbols, and generic
// IoT/cloud strings with the real Zig binary output forces them to spend time
// chasing false leads before identifying the actual language and framework.
//
// All symbols are exported so the linker cannot dead-strip them under
// --gc-sections. The symbol names are stripped from the final binary by
// builder.py's objcopy pass; only the data survives.
//
// None of these strings affect runtime behavior.

// ---------------------------------------------------------------------------
// Go runtime lookalikes
// ---------------------------------------------------------------------------
pub export const _d_go_00 = "runtime.goexit".*;
pub export const _d_go_01 = "runtime.newproc".*;
pub export const _d_go_02 = "runtime.mallocgc".*;
pub export const _d_go_03 = "runtime.morestack_noctxt".*;
pub export const _d_go_04 = "runtime.gcBgMarkWorker".*;
pub export const _d_go_05 = "sync.(*Mutex).Lock".*;
pub export const _d_go_06 = "sync.(*WaitGroup).Wait".*;
pub export const _d_go_07 = "net/http.(*Transport).roundTrip".*;
pub export const _d_go_08 = "crypto/tls.(*Conn).Handshake".*;
pub export const _d_go_09 = "encoding/json.Marshal".*;
pub export const _d_go_10 = "os.(*File).Read".*;
pub export const _d_go_11 = "goroutine".*;

// ---------------------------------------------------------------------------
// Rust runtime lookalikes
// ---------------------------------------------------------------------------
pub export const _d_rs_00 = "core::result::unwrap_failed".*;
pub export const _d_rs_01 = "alloc::raw_vec::capacity_overflow".*;
pub export const _d_rs_02 = "std::panicking::begin_panic".*;
pub export const _d_rs_03 = "core::slice::index_failed".*;
pub export const _d_rs_04 = "tokio::runtime::task::harness".*;
pub export const _d_rs_05 = "hyper::client::conn::http1".*;
pub export const _d_rs_06 = "rustc_demangle".*;

// ---------------------------------------------------------------------------
// C++ / Qt lookalikes
// ---------------------------------------------------------------------------
pub export const _d_cxx_00 = "QCoreApplication::exec".*;
pub export const _d_cxx_01 = "QObject::connect".*;
pub export const _d_cxx_02 = "QString::fromStdString".*;
pub export const _d_cxx_03 = "QNetworkAccessManager".*;
pub export const _d_cxx_04 = "std::__throw_bad_alloc".*;
pub export const _d_cxx_05 = "std::__throw_length_error".*;
pub export const _d_cxx_06 = "_ZNSt6vectorIiSaIiEE".*;

// ---------------------------------------------------------------------------
// Plausible IoT / cloud platform strings
// ---------------------------------------------------------------------------
pub export const _d_iot_00 = "iot.amazonaws.com".*;
pub export const _d_iot_01 = "hub.azure-devices.net".*;
pub export const _d_iot_02 = "cloud.thethings.network".*;
pub export const _d_iot_03 = "mqtt.googleapis.com".*;
pub export const _d_iot_04 = "api.cloudflare.com".*;
pub export const _d_iot_05 = "telemetry.events".*;
pub export const _d_iot_06 = "device-shadow/update".*;
pub export const _d_iot_07 = "application/x-www-form-urlencoded".*;
pub export const _d_iot_08 = "X-Amz-Date".*;
pub export const _d_iot_09 = "Authorization: Bearer".*;

// ---------------------------------------------------------------------------
// Plausible error / log strings (mixed framework style)
// ---------------------------------------------------------------------------
pub export const _d_log_00 = "connection refused".*;
pub export const _d_log_01 = "TLS handshake timeout".*;
pub export const _d_log_02 = "certificate verify failed".*;
pub export const _d_log_03 = "unexpected EOF".*;
pub export const _d_log_04 = "context deadline exceeded".*;
pub export const _d_log_05 = "dial tcp: lookup".*;
pub export const _d_log_06 = "i/o timeout".*;
pub export const _d_log_07 = "broken pipe".*;
pub export const _d_log_08 = "no such file or directory".*;
pub export const _d_log_09 = "permission denied".*;
