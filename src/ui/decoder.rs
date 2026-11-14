//! Decode password tool: a multi-core numeric brute force for a forgotten open-password, with
//! instant owner-restriction stripping, encryption analysis, a known-pattern mask, a live
//! progress bar with ETA, and a ready-to-run hashcat command for the GPU route.
//!
//! The search runs on a background thread (so the window stays responsive) and reports progress
//! through a shared [`Progress`]; the final result arrives over a channel.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Instant;

use anyhow::Result;
use eframe::egui::{self, RichText, Vec2};

use super::theme::*;
use crate::engine::{self, Found, LockState};
use crate::progress::{self, Progress};

struct Running {
    progress: Progress,
    rx: Receiver<Result<Found>>,
    started: Instant,
}

pub struct DecoderState {
    file: Option<PathBuf>,
    min_len: u32,
    max_len: u32,
    pattern: String,
    log: Vec<String>,
    running: Option<Running>,
    /// The recovered open-password, kept so we can offer to open or save a copy.
    found: Option<String>,
}

impl Default for DecoderState {
    fn default() -> Self {
        Self {
            file: None,
            min_len: 1,
            max_len: 6,
            pattern: String::new(),
            log: Vec::new(),
            running: None,
            found: None,
        }
    }
}

impl DecoderState {
    pub fn running(&self) -> bool {
        self.running.is_some()
    }

    pub fn set_file(&mut self, path: PathBuf) {
        self.file = Some(path);
    }

    fn log(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        self.poll();

        // File row.
        card(ui, |ui| {
            ui.label(strong("PDF file"));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let name = self
                    .file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "No file selected".into());
                ui.add(egui::Label::new(secondary(ui, name)).truncate());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if command(ui, !self.running(), I_FOLDER, "Browse…") {
                        if let Some(p) = super::pick_pdf("Choose a PDF") {
                            self.file = Some(p);
                        }
                    }
                });
            });
        });

        // Options.
        let busy = self.running();
        ui.add_enabled_ui(!busy, |ui| {
            card(ui, |ui| {
                ui.label(strong("Options"));
                ui.add_space(4.0);
                egui::Grid::new("decode_opts")
                    .num_columns(2)
                    .spacing(Vec2::new(12.0, 8.0))
                    .show(ui, |ui| {
                        ui.label("Digit length");
                        ui.horizontal(|ui| {
                            ui.add(egui::DragValue::new(&mut self.min_len).range(1..=18).prefix("min "));
                            ui.add(egui::DragValue::new(&mut self.max_len).range(1..=18).prefix("max "));
                            if self.max_len < self.min_len {
                                self.max_len = self.min_len;
                            }
                        });
                        ui.end_row();
                        ui.label("Known pattern");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.pattern)
                                .hint_text("e.g. 077???????  ('?' = unknown digit)")
                                .desired_width(260.0),
                        );
                        ui.end_row();
                    });
                caption(ui, "A pattern overrides the digit length. '?' marks each unknown digit.");
            });
        });

        // Actions.
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if accent_button(ui, !busy && self.file.is_some(), &labeled(I_UNLOCK, "Start")) {
                self.start(ui.ctx());
            }
            let p = Palette::current(ui);
            let stop = egui::Button::new(strong(labeled(I_CLOSE, "Stop")).color(p.on_accent))
                .fill(p.error)
                .min_size(Vec2::new(120.0, 34.0));
            if ui.add_enabled(busy, stop).clicked() {
                if let Some(r) = &self.running {
                    r.progress.cancel();
                }
            }
        });

        // Progress.
        if let Some(r) = &self.running {
            ui.add_space(8.0);
            let p = Palette::current(ui);
            let frac = r.progress.fraction().unwrap_or(0.0);
            let elapsed = r.started.elapsed().as_secs();
            ui.add(
                egui::ProgressBar::new(frac)
                    .desired_height(6.0)
                    .fill(p.accent)
                    .corner_radius(3.0),
            );
            ui.horizontal(|ui| {
                ui.spinner();
                let stage = r.progress.stage();
                let stage = if stage.is_empty() { "Starting".into() } else { stage };
                ui.label(secondary(ui, format!("{stage} · {}:{:02} elapsed", elapsed / 60, elapsed % 60)));
            });
        }

        // After a password is found: ask what to do with it.
        if !self.running() && self.found.is_some() {
            self.found_card(ui);
        }

        // Log.
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.label(strong("Log"));
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if self.log.is_empty() {
                        caption(ui, "Results and guidance appear here.");
                    }
                    for line in &self.log {
                        ui.label(RichText::new(line).monospace().size(12.0));
                    }
                });
        });
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Some(path) = self.file.clone() else { return };
        self.log.clear();
        self.found = None;

        // Fast paths that avoid brute forcing entirely.
        match engine::open_state(&path) {
            Ok(LockState::Plain) => {
                self.log("This PDF opens without a password - nothing to brute force.");
                return;
            }
            Ok(LockState::Owner) => {
                let out = unlocked_path(&path);
                match engine::strip_restrictions(&path, &out) {
                    Ok(()) => {
                        self.log("[+] Owner-password only - the file opened freely.");
                        self.log(format!("[+] Restrictions removed → {}", out.display()));
                    }
                    Err(e) => self.log(format!("[!] {e:#}")),
                }
                return;
            }
            Ok(LockState::User) => {}
            Err(e) => {
                self.log(format!("[!] {e:#}"));
                return;
            }
        }

        // Real open-password brute force. Report the encryption first.
        if let Ok(enc) = engine::analyze_encryption(&path) {
            self.log(format!("[*] Encryption: {}", enc.label));
            if let Some(m) = enc.hashcat_mode {
                self.log(format!("[*] hashcat mode: -m {m}"));
            }
            if enc.strong {
                self.log("[!] AES-256 is extremely slow to brute force, even on a GPU.");
            }
        }

        let mask = self.pattern.trim().to_string();
        let ks = engine::keyspace(self.min_len, self.max_len, &mask);
        let workers = rayon::current_num_threads();
        let est = engine::rough_cpu_seconds(ks, workers);
        self.log(format!(
            "[*] Search space: {} combinations · ~{} on {} core(s).",
            engine::group(ks),
            engine::fmt_time(est),
            workers
        ));
        if est > 3600.0 {
            self.log("[!] This is impractical on a CPU. The GPU route (hashcat):");
            if let Ok(enc) = engine::analyze_encryption(&path) {
                for l in engine::hashcat_command(&path, enc.hashcat_mode, self.min_len, self.max_len).lines() {
                    self.log(l.to_string());
                }
            }
            self.log("[*] Starting the CPU search anyway - press Stop to cancel.");
        }

        let label = if mask.is_empty() {
            format!("{}–{} digits", self.min_len, self.max_len)
        } else {
            format!("pattern {mask}")
        };
        self.log(format!("[*] Brute forcing {label} on {workers} core(s)…"));

        let progress = Progress::default();
        let task_pr = progress.clone();
        let (min_len, max_len) = (self.min_len, self.max_len);
        let ctx = ctx.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = engine::run_search(&path, min_len, max_len, &mask, &task_pr);
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.running = Some(Running {
            progress,
            rx,
            started: Instant::now(),
        });
    }

    fn poll(&mut self) {
        let Some(r) = &self.running else { return };
        let result = match r.rx.try_recv() {
            Ok(res) => res,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!("The search stopped unexpectedly")),
        };
        let elapsed = engine::fmt_time(r.started.elapsed().as_secs_f64());
        self.running = None;
        match result {
            Ok(Found::Password(pw)) => {
                self.log(format!("[+] FOUND: {pw}  (in {elapsed})"));
                self.found = Some(pw);
            }
            Ok(Found::NotFound) => {
                self.log(format!("[-] No numeric password found in this range ({elapsed})."));
            }
            Err(e) if progress::is_cancelled(&e) => {
                self.log(format!("[*] Stopped after {elapsed}. Nothing was saved."));
            }
            Err(e) => self.log(format!("[!] Error: {e:#}")),
        }
    }

    /// The "password found" card: show it and offer to open the PDF or save a decrypted copy.
    fn found_card(&mut self, ui: &mut egui::Ui) {
        let pw = self.found.clone().unwrap_or_default();
        let p = Palette::current(ui);
        let mut open_it = false;
        let mut save_it = false;
        let mut dismiss = false;

        ui.add_space(8.0);
        egui::Frame::new()
            .fill(p.success_bg)
            .stroke(egui::Stroke::new(1.0, p.border))
            .corner_radius(8.0)
            .inner_margin(egui::Margin::symmetric(16, 14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(I_CHECK).color(p.success).size(18.0));
                    ui.add_space(6.0);
                    ui.label(strong(format!("Password found:  {pw}")));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icon_button(ui, true, I_CLOSE, "Dismiss") {
                            dismiss = true;
                        }
                    });
                });
                ui.add_space(4.0);
                caption(
                    ui,
                    "Open the PDF now using this password, or save a decrypted copy with the password removed.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if accent_button(ui, true, &labeled(I_OPEN, "Open it for me")) {
                        open_it = true;
                    }
                    if ui.button(labeled(I_SAVE, "Save decrypted copy…")).clicked() {
                        save_it = true;
                    }
                });
            });

        if open_it {
            self.open_found(&pw);
        }
        if save_it {
            self.save_found(&pw);
        }
        if dismiss {
            self.found = None;
        }
    }

    /// Decrypt to a temporary copy with the found password and launch the default PDF viewer.
    fn open_found(&mut self, pw: &str) {
        let Some(path) = self.file.clone() else { return };
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        let out = std::env::temp_dir().join(format!("{stem}_opened.pdf"));
        match engine::save_unlocked(&path, pw, &out) {
            Ok(()) => {
                let _ = super::open_path(&out);
                self.log(format!("[+] Opened → {}", out.display()));
            }
            Err(e) => self.log(format!("[!] Could not open: {e:#}")),
        }
    }

    /// Ask where to save, then write a decrypted (password-removed) copy.
    fn save_found(&mut self, pw: &str) {
        let Some(path) = self.file.clone() else { return };
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        let Some(dest) = rfd::FileDialog::new()
            .set_title("Save decrypted copy as")
            .set_file_name(format!("{stem}_unlocked.pdf"))
            .add_filter("PDF files", &["pdf"])
            .save_file()
        else {
            return;
        };
        match engine::save_unlocked(&path, pw, &dest) {
            Ok(()) => self.log(format!("[+] Decrypted copy → {}", dest.display())),
            Err(e) => self.log(format!("[!] Could not save a copy: {e:#}")),
        }
    }
}

fn unlocked_path(path: &PathBuf) -> PathBuf {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    path.with_file_name(format!("{stem}_unlocked.pdf"))
}
