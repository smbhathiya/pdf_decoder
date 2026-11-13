// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod engine;
mod progress;
mod secret;
mod startup;
mod ui;
mod vault;

const APP_TITLE: &str = "PDF Decoder";

fn options(renderer: eframe::Renderer) -> eframe::NativeOptions {
    eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_TITLE)
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([820.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    }
}

/// Open the window with one graphics backend. A panic inside the backend counts as a failure.
fn run(renderer: eframe::Renderer, name: &'static str) -> Result<(), String> {
    startup::log(&format!("starting with {name}"));
    let result = std::panic::catch_unwind(|| {
        eframe::run_native(
            APP_TITLE,
            options(renderer),
            Box::new(move |cc| {
                startup::log(&format!("{name} is working"));
                if name == "DirectX/Vulkan" {
                    startup::write_marker("wgpu-ok");
                }
                Ok(Box::new(ui::App::new(cc)))
            }),
        )
    });
    let result = match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("the graphics driver stopped unexpectedly".into()),
    };
    if let Err(e) = &result {
        startup::log(&format!("{name} failed: {e}"));
    }
    result
}

const RENDERER_ENV: &str = "PDFDECODER_RENDERER";
const FIRST_ERROR_ENV: &str = "PDFDECODER_FIRST_RENDERER_ERROR";

fn show_startup_error(details: &str) {
    rfd::MessageDialog::new()
        .set_title(APP_TITLE)
        .set_description(format!(
            "{APP_TITLE} could not start because the graphics system is not available.\n\n\
             Please update your graphics driver and try again.\n\nDetails:\n{details}\n\n\
             A log was saved to:\n{}",
            startup::log_path().display()
        ))
        .set_level(rfd::MessageLevel::Error)
        .show();
}

fn main() {
    startup::install_panic_hook();
    startup::log(&format!(
        "{APP_TITLE} {} ({}) on {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        startup::windows_version()
    ));

    // DirectX 12 / Vulkan first (fast, modern); fall back to OpenGL by restarting the process.
    let marker = startup::read_marker();
    let forced = std::env::var(RENDERER_ENV).is_ok_and(|v| v.eq_ignore_ascii_case("gl"));
    let use_gl = forced || marker == "gl" || marker == "wgpu-starting";
    if marker == "wgpu-starting" {
        startup::log("previous start crashed during DirectX/Vulkan setup; using OpenGL");
        startup::write_marker("gl");
    }

    if !use_gl {
        startup::write_marker("wgpu-starting");
        let Err(wgpu_error) = run(eframe::Renderer::Wgpu, "DirectX/Vulkan") else {
            return;
        };
        startup::write_marker("gl");
        let restarted = std::env::current_exe().and_then(|exe| {
            std::process::Command::new(exe)
                .args(std::env::args_os().skip(1))
                .env(RENDERER_ENV, "gl")
                .env(FIRST_ERROR_ENV, &wgpu_error)
                .spawn()
        });
        if let Err(e) = restarted {
            startup::log(&format!("restart with OpenGL failed: {e}"));
            show_startup_error(&format!(
                "• DirectX/Vulkan: {wgpu_error}\n• Restart with OpenGL: {e}"
            ));
            std::process::exit(1);
        }
        return;
    }

    if let Err(gl_error) = run(eframe::Renderer::Glow, "OpenGL") {
        startup::write_marker("");
        let first = std::env::var(FIRST_ERROR_ENV).unwrap_or_else(|_| "not tried".into());
        show_startup_error(&format!("• DirectX/Vulkan: {first}\n• OpenGL: {gl_error}"));
        std::process::exit(1);
    }
}
