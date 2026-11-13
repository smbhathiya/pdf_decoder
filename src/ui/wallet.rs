//! Passwords tool: a wallet of reusable named passwords. The Open PDF tool tries these
//! automatically; here the user manages them and can test the wallet against any PDF.

use eframe::egui::{self, RichText, Vec2};

use super::theme::*;
use super::{Status, pick_pdf};
use crate::vault::{Password, Vault};

#[derive(Default)]
pub struct WalletState {
    passwords: Vec<Password>,
    loaded: bool,
    selected: Option<i64>,
    name_in: String,
    pw_in: String,
    show: bool,
}

impl WalletState {
    fn reload(&mut self, vault: &Vault) {
        self.passwords = vault.passwords().unwrap_or_default();
        self.loaded = true;
        if !self.passwords.iter().any(|p| Some(p.id) == self.selected) {
            self.selected = None;
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, vault: &Vault, status: &mut Status) {
        if !self.loaded {
            self.reload(vault);
        }

        // Add row.
        card(ui, |ui| {
            ui.label(strong("Add a password"));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Name");
                ui.add(egui::TextEdit::singleline(&mut self.name_in).desired_width(140.0));
                ui.label("Password");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.pw_in)
                        .password(!self.show)
                        .desired_width(180.0),
                );
                ui.checkbox(&mut self.show, "Show");
                let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if accent_button(ui, !self.pw_in.is_empty(), &labeled(I_ADD, "Add")) || submit {
                    match vault.add_password(&self.name_in, &self.pw_in) {
                        Ok(()) => {
                            self.name_in.clear();
                            self.pw_in.clear();
                            self.reload(vault);
                            *status = Some((true, "Added to the wallet.".into()));
                        }
                        Err(e) => *status = Some((false, format!("{e:#}"))),
                    }
                }
            });
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if command(ui, true, I_UNLOCK, "Test on a PDF…") {
                if let Some(path) = pick_pdf("Pick a PDF to test the wallet against") {
                    *status = Some(match vault.find_match(&path) {
                        Ok(Some(m)) if m.password.is_empty() => {
                            (true, "This PDF needs no open password.".into())
                        }
                        Ok(Some(m)) => (true, format!("'{}' opens this PDF. ✓", m.name)),
                        Ok(None) => (false, "None of the wallet passwords open this PDF.".into()),
                        Err(e) => (false, format!("{e:#}")),
                    });
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if command(ui, self.selected.is_some(), I_DELETE, "Remove") {
                    if let Some(id) = self.selected {
                        let _ = vault.remove_password(id);
                        self.reload(vault);
                        *status = Some((true, "Removed from the wallet.".into()));
                    }
                }
            });
        });

        ui.add_space(6.0);

        if self.passwords.is_empty() {
            card(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(24.0);
                    ui.label(RichText::new(I_LOCK).size(28.0).color(Palette::current(ui).text2));
                    ui.label(strong("No passwords yet"));
                    caption(ui, "Add one above. Names help you tell them apart.");
                    ui.add_space(24.0);
                });
            });
        } else {
            let p = Palette::current(ui);
            card(ui, |ui| {
                egui::Grid::new("wallet_list")
                    .num_columns(2)
                    .striped(true)
                    .spacing(Vec2::new(16.0, 8.0))
                    .show(ui, |ui| {
                        ui.label(strong("NAME").size(12.0));
                        ui.label(strong("PASSWORD").size(12.0));
                        ui.end_row();
                        let mut clicked = None;
                        for pw in &self.passwords {
                            let selected = Some(pw.id) == self.selected;
                            let name = RichText::new(&pw.name);
                            let name = if selected { name.color(p.accent) } else { name };
                            if ui.selectable_label(selected, name).clicked() {
                                clicked = Some(pw.id);
                            }
                            let shown = if self.show {
                                pw.password.clone()
                            } else {
                                "•".repeat(pw.password.chars().count().max(1))
                            };
                            ui.label(secondary(ui, shown));
                            ui.end_row();
                        }
                        if let Some(id) = clicked {
                            self.selected =
                                if self.selected == Some(id) { None } else { Some(id) };
                        }
                    });
            });
        }

        caption(
            ui,
            &format!("{} password(s) saved · sealed with Windows DPAPI on this account.", self.passwords.len()),
        );
    }
}
