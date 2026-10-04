//! Minimal C ABI for the recovery core.
//!
//! Design (task 1.2):
//! - Opaque `RecoverySession*` handle created/freed by the host.
//! - Every request is a UTF-8 JSON string; every result is an owned UTF-8 JSON buffer the host
//!   frees with [`recovery_string_free`].
//! - Progress is delivered through a C callback with a `void* user_data` cookie.
//! - Cancellation is a flag flipped with [`recovery_session_cancel`] from any thread.
//! - Errors are structured JSON `{code, message, path?, remedy?}` and never contain secrets.
//! - Passwords are passed as a pointer+length and copied into zeroizing memory immediately.
//!
//! The header `include/recovery_ffi.h` is maintained by hand to match these signatures so the
//! Swift package builds without cbindgen or Xcode.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::sync::Mutex;

use recovery_core::progress::{CallbackSink, CancelToken, ProgressEvent, ProgressSink};
use recovery_core::secret::Password;
use recovery_core::session::driver::{Driver, Request};
use recovery_core::{ErrorCode, RecoveryError};

/// Progress callback: `(stage, done, total, user_data)`. `stage` is a NUL-terminated UTF-8 string
/// valid only for the duration of the call.
pub type RecoveryProgressFn = Option<unsafe extern "C" fn(*const c_char, u64, u64, *mut c_void)>;

struct ProgressBridge {
    callback: RecoveryProgressFn,
    user_data: *mut c_void,
}

// SAFETY: the host promises the callback and cookie are usable from the worker thread that
// runs the operation; this mirrors the common libdispatch pattern.
unsafe impl Send for ProgressBridge {}
unsafe impl Sync for ProgressBridge {}

impl ProgressBridge {
    fn emit(&self, ev: ProgressEvent) {
        if let Some(cb) = self.callback {
            let stage = CString::new(ev.stage.as_str()).expect("static stage name");
            // SAFETY: pointer is valid for the duration of the call; host must not retain it.
            unsafe { cb(stage.as_ptr(), ev.done, ev.total, self.user_data) };
        }
    }
}

/// Opaque session handle.
pub struct RecoverySession {
    driver: Mutex<Driver>,
    cancel: CancelToken,
}

fn to_owned_cstring(s: String) -> *mut c_char {
    // JSON produced by serde never contains NUL; fall back defensively.
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new("{\"error\":{\"code\":\"internal\",\"message\":\"NUL in output\"}}")
            .expect("literal")
            .into_raw(),
    }
}

fn error_json(err: &RecoveryError) -> String {
    serde_json::json!({ "error": err }).to_string()
}

/// Library version as a static NUL-terminated string. Do not free.
#[no_mangle]
pub extern "C" fn recovery_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

/// Create a session bound to `workspace_dir` (UTF-8, NUL-terminated). Returns NULL on failure
/// and writes an error JSON to `*err_out` (host frees it) when `err_out` is non-NULL.
///
/// # Safety
/// `workspace_dir` must be NULL or a valid NUL-terminated string; `err_out` must be NULL or a
/// valid, writable pointer for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn recovery_session_new(
    workspace_dir: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut RecoverySession {
    let set_err = |e: RecoveryError| {
        if !err_out.is_null() {
            // SAFETY: caller guarantees err_out is a valid out-pointer.
            unsafe { *err_out = to_owned_cstring(error_json(&e)) };
        }
        ptr::null_mut()
    };
    if workspace_dir.is_null() {
        return set_err(RecoveryError::new(
            ErrorCode::InvalidArgument,
            "workspace_dir is NULL",
        ));
    }
    // SAFETY: caller guarantees a valid NUL-terminated string.
    let ws = match unsafe { CStr::from_ptr(workspace_dir) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return set_err(RecoveryError::new(
                ErrorCode::InvalidArgument,
                "workspace_dir is not UTF-8",
            ))
        }
    };
    match Driver::open(std::path::Path::new(ws)) {
        Ok(driver) => Box::into_raw(Box::new(RecoverySession {
            driver: Mutex::new(driver),
            cancel: CancelToken::new(),
        })),
        Err(e) => set_err(e),
    }
}

/// Release a session. Safe to call with NULL. Secrets held by the session are zeroized.
///
/// # Safety
/// `session` must be NULL or a pointer returned by `recovery_session_new` that has not been
/// freed, and no other call may use it concurrently or afterwards.
#[no_mangle]
pub unsafe extern "C" fn recovery_session_free(session: *mut RecoverySession) {
    if !session.is_null() {
        // SAFETY: pointer came from `recovery_session_new` and is freed exactly once.
        drop(unsafe { Box::from_raw(session) });
    }
}

/// Request cancellation of the operation currently running on `session`. Thread-safe.
///
/// # Safety
/// `session` must be NULL or a live pointer from `recovery_session_new`.
#[no_mangle]
pub unsafe extern "C" fn recovery_session_cancel(session: *mut RecoverySession) {
    if let Some(s) = unsafe { session.as_ref() } {
        s.cancel.cancel();
    }
}

/// Execute a JSON request. `password`/`password_len` may be NULL/0 when the request needs none.
/// Returns an owned JSON string: `{"ok": ...}` or `{"error": {...}}`. Never NULL.
///
/// # Safety
/// `session` must be a live pointer from `recovery_session_new`; `request_json` a valid
/// NUL-terminated string; `password` NULL or readable for `password_len` bytes; `progress`, if
/// non-NULL, must be callable with `user_data` from the calling thread for the whole call.
#[no_mangle]
pub unsafe extern "C" fn recovery_session_execute(
    session: *mut RecoverySession,
    request_json: *const c_char,
    password: *const u8,
    password_len: usize,
    progress: RecoveryProgressFn,
    user_data: *mut c_void,
) -> *mut c_char {
    let Some(s) = (unsafe { session.as_ref() }) else {
        return to_owned_cstring(error_json(&RecoveryError::new(
            ErrorCode::InvalidArgument,
            "session is NULL",
        )));
    };
    if request_json.is_null() {
        return to_owned_cstring(error_json(&RecoveryError::new(
            ErrorCode::InvalidArgument,
            "request_json is NULL",
        )));
    }
    let req_str = match unsafe { CStr::from_ptr(request_json) }.to_str() {
        Ok(r) => r,
        Err(_) => {
            return to_owned_cstring(error_json(&RecoveryError::new(
                ErrorCode::InvalidArgument,
                "request_json is not UTF-8",
            )))
        }
    };
    let request: Request = match serde_json::from_str(req_str) {
        Ok(r) => r,
        Err(e) => {
            return to_owned_cstring(error_json(&RecoveryError::new(
                ErrorCode::InvalidArgument,
                format!("request: {e}"),
            )))
        }
    };
    let pw = if password.is_null() || password_len == 0 {
        None
    } else {
        // SAFETY: caller guarantees `password_len` readable bytes. Copied into zeroizing memory.
        Some(Password::from_bytes(unsafe {
            std::slice::from_raw_parts(password, password_len)
        }))
    };

    s.cancel.reset();
    let bridge = ProgressBridge {
        callback: progress,
        user_data,
    };
    let sink = CallbackSink::new(s.cancel.clone(), move |ev| bridge.emit(ev));

    let mut driver = match s.driver.lock() {
        Ok(d) => d,
        Err(_) => {
            return to_owned_cstring(error_json(&RecoveryError::internal(
                "session mutex poisoned",
            )))
        }
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        driver.execute(request, pw, &sink as &dyn ProgressSink)
    }));
    let out = match outcome {
        Ok(Ok(v)) => serde_json::json!({ "ok": v }).to_string(),
        Ok(Err(e)) => error_json(&e),
        Err(_) => error_json(&RecoveryError::internal(
            "internal panic in recovery core; no secrets were logged",
        )),
    };
    to_owned_cstring(out)
}

/// Free a string returned by this library. Safe to call with NULL.
///
/// # Safety
/// `s` must be NULL or a pointer returned by this library that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn recovery_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: pointer came from `CString::into_raw` in this crate.
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lifecycle_and_bad_args() {
        let dir = tempfile::tempdir().unwrap();
        let ws = CString::new(dir.path().to_str().unwrap()).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let s = unsafe { recovery_session_new(ws.as_ptr(), &mut err) };
        assert!(!s.is_null());
        assert!(err.is_null());
        let req = CString::new(r#"{"op":"ping"}"#).unwrap();
        let out = unsafe {
            recovery_session_execute(s, req.as_ptr(), ptr::null(), 0, None, ptr::null_mut())
        };
        let txt = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_owned();
        unsafe { recovery_string_free(out) };
        assert!(txt.contains("\"ok\""), "{txt}");
        unsafe { recovery_session_free(s) };
        // NULL safety
        unsafe {
            recovery_session_free(ptr::null_mut());
            recovery_string_free(ptr::null_mut());
            recovery_session_cancel(ptr::null_mut());
        }
        let s2 = unsafe { recovery_session_new(ptr::null(), &mut err) };
        assert!(s2.is_null());
        assert!(!err.is_null());
        unsafe { recovery_string_free(err) };
    }
}
