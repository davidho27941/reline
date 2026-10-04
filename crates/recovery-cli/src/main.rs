//! `reline`: expert CLI and test harness.
//!
//! Usage:
//!   reline <workspace> <request-json> [--password-env VAR]
//!   reline version
//!
//! The request JSON mirrors the FFI contract exactly, so every CLI run exercises the same
//! driver the SwiftUI shell uses. Passwords are read from an environment variable or stdin,
//! never from argv (argv is visible to other processes).

use std::io::Read;
use std::path::Path;

use recovery_core::progress::{CallbackSink, CancelToken, ProgressSink};
use recovery_core::secret::Password;
use recovery_core::session::driver::{Driver, Request};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "version" {
        println!("{}", recovery_core::CORE_VERSION);
        return;
    }
    if args.len() < 3 {
        eprintln!(
            "usage: reline <workspace> <request-json> [--password-env VAR | --password-stdin]"
        );
        std::process::exit(2);
    }
    let workspace = Path::new(&args[1]);
    let request: Request = match serde_json::from_str(&args[2]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid request: {e}");
            std::process::exit(2);
        }
    };
    let mut password = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--password-env" => {
                i += 1;
                let var = args.get(i).expect("--password-env VAR");
                match std::env::var_os(var) {
                    Some(v) => password = Some(Password::from_bytes(v.as_encoded_bytes())),
                    None => {
                        eprintln!("environment variable {var} is not set");
                        std::process::exit(2);
                    }
                }
            }
            "--password-stdin" => {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf).expect("stdin");
                let trimmed = buf.trim_end_matches(['\n', '\r']);
                password = Some(Password::new(trimmed));
            }
            other => {
                eprintln!("unknown flag {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let token = CancelToken::new();
    let sink = CallbackSink::new(token, |ev| {
        if ev.total > 0 {
            eprintln!("[{}] {}/{}", ev.stage.as_str(), ev.done, ev.total);
        }
    });

    let mut driver = match Driver::open(workspace) {
        Ok(d) => d,
        Err(e) => {
            println!("{}", serde_json::json!({ "error": e }));
            std::process::exit(1);
        }
    };
    match driver.execute(request, password, &sink as &dyn ProgressSink) {
        Ok(v) => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "ok": v })).unwrap()
        ),
        Err(e) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "error": e })).unwrap()
            );
            std::process::exit(1);
        }
    }
}
