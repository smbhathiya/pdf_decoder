//! Open PDF tool: a table of saved PDFs, opened (decrypted to a temp copy and launched) in one
//! click. Adding a PDF first tries the wallet passwords, so the user usually types nothing.

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText, Vec2};

use super::theme::*;
use super::{Status, open_path, pick_pdf};
use crate::engine;
use crate::vault::{Entry, Vault};

/// The inline "add a PDF" form.
struct AddFlow {
    path: PathBuf,
    password: String,
    show: bool,
    save_to_wallet: bool,
    label: String,
    /// A wallet password already verified to open this file (skip typing).
    matched: bool,
    error: Option<String>,
}

#[derive(Default)]
pub struct OpenerState {
    entries: Vec<Entry>,
    loaded: bool,
    selected: Option<i64>,
    add: Option<AddFlow>,
}

impl OpenerState {
    /// Called from a file drop: begin the add flow for `path`.
    pub fn stage_add(&mut self, path: PathBuf) {
        self.begin_add(None, path);
    }

    fn begin_add(&mut self, vault: Option<&Vault>, path: PathBuf) {
        let matched = vault
            .and_then(|v| v.find_match(&path).ok().flatten())
            .filter(|m| !m.password.is_empty());
        let label = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        self.add = Some(AddFlow {
            path,
            password: matched
                .as_ref()
                .map(|m| m.password.clone())
                .unwrap_or_default(),
            show: false,
            save_to_wallet: true,
            label,
            matched: matched.is_some(),
            error: None,
        });
    }

    fn reload(&mut self, vault: &Vault) {
        self.entries = vault.entries().unwrap_or_default();
        self.loaded = true;
        if !self.entries.iter().any(|e| Some(e.id) == self.selected) {
            self.selected = None;
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, vault: &Vault, status: &mut Status) {
        if !self.loaded {
            self.reload(vault);
        }

        // Command bar.
        ui.horizontal(|ui| {
            if accent_button(ui, self.add.is_none(), &labeled(I_ADD, "Add PDF")) {
                if let Some(path) = pick_pdf("Choose a PDF") {
                    self.begin_add(Some(vault), path);
                }
            }
            let sel = self.selected;
            if command(ui, sel.is_some(), I_OPEN, "Open") {
                self.open_selected(status);
            }
            if command(ui, sel.is_some(), I_SAVE, "Save unlocked copy") {
                self.save_copy(status);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if command(ui, sel.is_some(), I_DELETE, "Remove") {
                    if let Some(id) = sel {
                        let _ = vault.remove_entry(id);
                        self.reload(vault);
                        *status = Some((true, "Removed from the list.".into()));
                    }
                }
            });
        });

        // Add form.
        if self.add.is_some() {
            self.add_form(ui, vault, status);
        }

        ui.add_space(6.0);

        // Saved PDFs table.
        if self.entries.is_empty() {
            card(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(24.0);
                    ui.label(
                        RichText::new(I_DOCUMENT)
                            .size(28.0)
                            .color(Palette::current(ui).text2),
                    );
                    ui.label(strong("No PDFs saved yet"));
                    caption(ui, "Click “Add PDF” to save one, then open it in a click.");
                    ui.add_space(24.0);
                });
            });
        } else {
            self.table(ui);
        }

        caption(
            ui,
            "Tip: add common passwords in the Passwords tab so PDFs open automatically.",
        );
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let p = Palette::current(ui);
        card(ui, |ui| {
            egui::Grid::new("saved_pdfs")
                .num_columns(3)
                .striped(true)
                .spacing(Vec2::new(16.0, 8.0))
                .show(ui, |ui| {
                    ui.label(strong("NAME").size(12.0));
                    ui.label(strong("FILE").size(12.0));
                    ui.label(strong("ADDED").size(12.0));
                    ui.end_row();
                    let mut clicked = None;
                    for e in &self.entries {
                        let selected = Some(e.id) == self.selected;
                        let name = RichText::new(&e.label);
                        let name = if selected { name.color(p.accent) } else { name };
                        if ui.selectable_label(selected, name).clicked() {
                            clicked = Some(e.id);
                        }
                        ui.label(secondary(ui, short_path(&e.path)))
                            .on_hover_text(&e.path);
                        ui.label(secondary(ui, &e.added));
                        ui.end_row();
                    }
                    if let Some(id) = clicked {
                        self.selected = if self.selected == Some(id) {
                            None
                        } else {
                            Some(id)
                        };
                    }
                });
        });
    }

    fn add_form(&mut self, ui: &mut egui::Ui, vault: &Vault, status: &mut Status) {
        let mut do_add = false;
        let mut cancel = false;
        let add = self.add.as_mut().unwrap();
        card(ui, |ui| {
            ui.label(strong(format!(
                "{}  Add: {}",
                I_UNLOCK,
                add.path.file_name().and_then(|s| s.to_str()).unwrap_or("")
            )));
            if add.matched {
                caption(
                    ui,
                    "A saved wallet password opens this file - just confirm.",
                );
            } else {
                caption(ui, "Enter the password that opens this PDF.");
            }
            ui.add_space(6.0);
            egui::Grid::new("add_grid")
                .num_columns(2)
                .spacing(Vec2::new(10.0, 8.0))
                .show(ui, |ui| {
                    ui.label("Password");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut add.password)
                                .password(!add.show)
                                .desired_width(240.0),
                        );
                        ui.checkbox(&mut add.show, "Show");
                    });
                    ui.end_row();
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut add.label).desired_width(240.0));
                    ui.end_row();
                });
            ui.checkbox(
                &mut add.save_to_wallet,
                "Also save this password to the wallet",
            );
            if let Some(err) = &add.error {
                ui.colored_label(Palette::current(ui).error, err);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if accent_button(ui, true, &labeled(I_CHECK, "Add")) {
                    do_add = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });

        if cancel {
            self.add = None;
            return;
        }
        if do_add {
            let add = self.add.as_mut().unwrap();
            match vault.add_entry(&add.path, &add.password, &add.label) {
                Ok(()) => {
                    if add.save_to_wallet && !add.password.is_empty() {
                        let name = if add.label.trim().is_empty() {
                            "Saved".to_string()
                        } else {
                            add.label.trim().to_string()
                        };
                        let _ = vault.add_password(&name, &add.password);
                    }
                    *status = Some((true, "Saved. Select it and click Open.".into()));
                    self.add = None;
                    self.reload(vault);
                }
                Err(e) => add.error = Some(format!("{e:#}")),
            }
        }
    }

    fn entry(&self, id: i64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    fn open_selected(&mut self, status: &mut Status) {
        let Some(e) = self.selected.and_then(|id| self.entry(id)) else {
            return;
        };
        let src = PathBuf::from(&e.path);
        if !src.is_file() {
            *status = Some((false, format!("File no longer exists: {}", e.path)));
            return;
        }
        let out = std::env::temp_dir().join(format!(
            "{}_opened.pdf",
            src.file_stem().and_then(|s| s.to_str()).unwrap_or("pdf")
        ));
        match engine::save_unlocked(&src, &e.password, &out) {
            Ok(()) => {
                let _ = open_path(&out);
                *status = Some((true, format!("Opened → {}", out.display())));
            }
            Err(e) => *status = Some((false, format!("{e:#}"))),
        }
    }

    fn save_copy(&mut self, status: &mut Status) {
        let Some(e) = self.selected.and_then(|id| self.entry(id)) else {
            return;
        };
        let src = PathBuf::from(&e.path);
        let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("pdf");
        let Some(dest) = rfd::FileDialog::new()
            .set_title("Save unlocked copy as")
            .set_file_name(format!("{stem}_unlocked.pdf"))
            .add_filter("PDF files", &["pdf"])
            .save_file()
        else {
            return;
        };
        match engine::save_unlocked(&src, &e.password, &dest) {
            Ok(()) => *status = Some((true, format!("Saved unlocked copy → {}", dest.display()))),
            Err(e) => *status = Some((false, format!("{e:#}"))),
        }
    }
}

fn short_path(path: &str) -> String {
    let p = Path::new(path);
    match (p.parent().and_then(|d| d.file_name()), p.file_name()) {
        (Some(dir), Some(file)) => {
            format!("…\\{}\\{}", dir.to_string_lossy(), file.to_string_lossy())
        }
        (None, Some(file)) => file.to_string_lossy().into_owned(),
        _ => path.to_string(),
    }
}
