//! Start-up diagnostics: a log file, a crash dialog, and a memory of which graphics
//! backend works on this PC. Files live in `%LOCALAPPDATA%\PDF Decoder\`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

pub const APP_NAME: &str = "PDF Decoder";

/// `%LOCALAPPDATA%\PDF Decoder\` (also where the password database lives).
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(APP_NAME);
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn log_path() -> PathBuf {
    data_dir().join("startup.log")
}

/// Append a line to the start-up log (best effort; never fails the app).
pub fn log(line: &str) {
    let path = log_path();
    if fs::metadata(&path)
        .map(|m| m.len() > 256 * 1024)
        .unwrap_or(false)
    {
        let _ = fs::remove_file(&path);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{secs}] [pid {}] {line}", std::process::id());
    }
}

/// Windows version string, for the log.
pub fn windows_version() -> String {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        if let Ok(out) = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !v.is_empty() {
                return v;
            }
        }
    }
    std::env::consts::OS.to_string()
}

fn marker_path() -> PathBuf {
    data_dir().join("renderer.txt")
}

/// The remembered graphics state, tied to the app version (so an update retries DirectX/Vulkan).
pub fn read_marker() -> String {
    let text = fs::read_to_string(marker_path()).unwrap_or_default();
    let mut parts = text.split_whitespace();
    let state = parts.next().unwrap_or_default();
    match parts.next() {
        Some(env!("CARGO_PKG_VERSION")) => state.to_string(),
        None if state == "wgpu-starting" => state.to_string(),
        _ => String::new(),
    }
}

pub fn write_marker(value: &str) {
    let _ = fs::write(
        marker_path(),
        format!("{value} {}", env!("CARGO_PKG_VERSION")),
    );
}

/// Log panics and show them in a dialog instead of disappearing silently.
pub fn install_panic_hook() {
    static SHOWN: AtomicBool = AtomicBool::new(false);
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown error".into());
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        log(&format!(
            "PANIC in thread '{thread}' at {location}: {message}"
        ));
        if thread == "main" && !SHOWN.swap(true, Ordering::SeqCst) {
            rfd::MessageDialog::new()
                .set_title(APP_NAME)
                .set_description(format!(
                    "{APP_NAME} ran into a problem and has to close.\n\n{message}\n\n\
                     A log was saved to:\n{}",
                    log_path().display()
                ))
                .set_level(rfd::MessageLevel::Error)
                .show();
        }
    }));
}
