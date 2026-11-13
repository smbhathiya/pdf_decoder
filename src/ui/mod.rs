//! Application shell: a Home launcher with three tools - Open PDF, Passwords (wallet) and
//! Decode - each opening a full-window page with a back button, in the Fluent / Windows 11 look
//! borrowed from the sibling "Beez PDF Studio" app.

mod decoder;
mod opener;
mod theme;
mod update;
mod wallet;

use std::path::{Path, PathBuf};

use eframe::egui::{self, Align2, FontId, Margin, RichText, Sense, Stroke, StrokeKind, Vec2};

use theme::*;
use update::UpdateUi;

use crate::vault::Vault;

/// A quick one-line result banner shown at the bottom of a tool page.
pub type Status = Option<(bool, String)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Home,
    Opener,
    Wallet,
    Decoder,
}

impl Page {
    fn meta(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Page::Opener => (
                I_UNLOCK,
                "Open PDF",
                "Save a protected PDF once, then reopen it in a click.",
            ),
            Page::Wallet => (
                I_LOCK,
                "Passwords",
                "A wallet of reusable named passwords, tried against any PDF.",
            ),
            Page::Decoder => (
                I_GRID,
                "Decode password",
                "Multi-core numeric brute force for a forgotten open-password.",
            ),
            Page::Home => ("", "PDF Decoder", ""),
        }
    }
}

pub struct App {
    page: Page,
    vault: Result<Vault, String>,
    opener: opener::OpenerState,
    wallet: wallet::WalletState,
    decoder: decoder::DecoderState,
    update: UpdateUi,
    status: Status,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);
        install_theme(&cc.egui_ctx);
        let vault = Vault::open().map_err(|e| format!("{e:#}"));
        let mut app = Self {
            page: Page::Home,
            vault,
            opener: Default::default(),
            wallet: Default::default(),
            decoder: Default::default(),
            update: UpdateUi::new(&cc.egui_ctx),
            status: None,
        };
        // A PDF passed on the command line (e.g. Windows "Open with…") opens the Open PDF tool.
        if let Some(pdf) = std::env::args_os()
            .skip(1)
            .map(PathBuf::from)
            .find(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf")))
        {
            app.drop_pdf(pdf);
        }
        app
    }

    /// Route a dropped PDF to the current tool (or open it on Home).
    fn drop_pdf(&mut self, path: PathBuf) {
        match self.page {
            Page::Decoder => self.decoder.set_file(path),
            _ => {
                self.opener.stage_add(path);
                self.page = Page::Opener;
            }
        }
    }

    fn home(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(title("PDF Decoder"));
                ui.label(secondary(
                    ui,
                    "Work with password-protected PDFs you own. Everything stays on this PC.",
                ));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), theme_toggle);
        });

        if let Err(e) = &self.vault {
            ui.add_space(12.0);
            let p = Palette::current(ui);
            egui::Frame::new()
                .fill(p.error_bg)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(8.0)
                .inner_margin(Margin::symmetric(16, 12))
                .show(ui, |ui| {
                    ui.label(RichText::new(format!("{I_ERROR}  Password store unavailable")).color(p.error));
                    ui.label(secondary(ui, e));
                });
        }

        ui.add_space(24.0);
        let card_w = ((ui.available_width() - 24.0) / 3.0).clamp(240.0, 360.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = Vec2::splat(12.0);
            for page in [Page::Opener, Page::Wallet, Page::Decoder] {
                if tool_card(ui, page, card_w) {
                    self.status = None;
                    self.page = page;
                }
            }
        });

        ui.add_space(26.0);
        ui.label(secondary(
            ui,
            "For your own files / education only. Use it to recover access to PDFs you are authorised to open.",
        ));
    }

    fn tool_page(&mut self, ui: &mut egui::Ui, page: Page) {
        let (_, name, desc) = page.meta();
        ui.horizontal(|ui| {
            let back = egui::Button::new(RichText::new(I_BACK).size(14.0))
                .frame_when_inactive(false)
                .min_size(Vec2::splat(36.0));
            if ui.add(back).on_hover_text("Back to Home (Esc)").clicked() {
                self.page = Page::Home;
            }
            ui.add_space(4.0);
            let home = ui.add(
                egui::Label::new(title("Home").color(Palette::current(ui).text2))
                    .sense(Sense::click()),
            );
            if home.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                self.page = Page::Home;
            }
            ui.label(
                RichText::new(format!("  {I_RIGHT}  "))
                    .size(14.0)
                    .color(Palette::current(ui).text2),
            );
            ui.label(title(name));
        });
        ui.label(secondary(ui, desc));
        ui.add_space(12.0);

        let busy = self.update.busy();
        egui::ScrollArea::vertical()
            .id_salt(name)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(ui.available_width() - 12.0);
                ui.add_enabled_ui(!busy, |ui| match page {
                    Page::Opener => match &self.vault {
                        Ok(v) => self.opener.ui(ui, v, &mut self.status),
                        Err(e) => vault_error(ui, e),
                    },
                    Page::Wallet => match &self.vault {
                        Ok(v) => self.wallet.ui(ui, v, &mut self.status),
                        Err(e) => vault_error(ui, e),
                    },
                    Page::Decoder => self.decoder.ui(ui),
                    Page::Home => {}
                });
                ui.add_space(24.0);
            });
    }

    fn info_bar(&mut self, ui: &mut egui::Ui) {
        let Some((ok, msg)) = self.status.clone() else {
            return;
        };
        let p = Palette::current(ui);
        let (bg, fg, icon, head) = if ok {
            (p.success_bg, p.success, I_CHECK, "Done")
        } else {
            (p.error_bg, p.error, I_ERROR, "Something went wrong")
        };
        let mut close = false;
        egui::Frame::new()
            .fill(bg)
            .stroke(Stroke::new(1.0, p.border))
            .corner_radius(8.0)
            .inner_margin(Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(icon).color(fg).size(16.0));
                    ui.add_space(6.0);
                    ui.label(strong(head));
                    let (text, out) = match msg.rsplit_once(" → ") {
                        Some((t, path)) => (t.to_string(), Some(PathBuf::from(path.trim()))),
                        None => (msg.clone(), None),
                    };
                    ui.add(egui::Label::new(text).wrap());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icon_button(ui, true, I_CLOSE, "Dismiss") {
                            close = true;
                        }
                        if let Some(out) = out.filter(|_| ok) {
                            if out.is_file() && ui.button(labeled(I_OPEN, "Open file")).clicked() {
                                let _ = open_path(&out);
                            }
                            let dir = if out.is_dir() {
                                Some(out.clone())
                            } else {
                                out.parent().map(Path::to_path_buf)
                            };
                            if let Some(dir) = dir
                                && ui.button(labeled(I_FOLDER, "Show in folder")).clicked()
                            {
                                let _ = open_path(&dir);
                            }
                        }
                    });
                });
            });
        if close {
            self.status = None;
        }
    }
}

fn vault_error(ui: &mut egui::Ui, e: &str) {
    let p = Palette::current(ui);
    ui.label(RichText::new(format!("{I_ERROR}  The password store could not be opened.")).color(p.error));
    ui.label(secondary(ui, e));
}

fn theme_toggle(ui: &mut egui::Ui) {
    let dark = ui.visuals().dark_mode;
    let (icon, tip) = if dark {
        (I_SUN, "Switch to light mode")
    } else {
        (I_MOON, "Switch to dark mode")
    };
    if icon_button(ui, true, icon, tip) {
        ui.ctx()
            .set_theme(if dark { egui::Theme::Light } else { egui::Theme::Dark });
    }
}

fn tool_card(ui: &mut egui::Ui, page: Page, width: f32) -> bool {
    let (icon, name, desc) = page.meta();
    let p = Palette::current(ui);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 104.0), Sense::click());
    let painter = ui.painter();
    let hovered = resp.hovered();
    painter.rect_filled(rect, 8.0, if hovered { p.card_hover } else { p.card });
    painter.rect_stroke(rect, 8.0, Stroke::new(1.0, p.border), StrokeKind::Inside);

    let icon_box = egui::Rect::from_min_size(rect.min + Vec2::new(16.0, 16.0), Vec2::splat(40.0));
    painter.rect_filled(
        icon_box,
        6.0,
        p.accent.gamma_multiply(if p.dark { 0.18 } else { 0.12 }),
    );
    painter.text(
        icon_box.center(),
        Align2::CENTER_CENTER,
        icon,
        FontId::proportional(20.0),
        p.accent,
    );

    let x = icon_box.right() + 14.0;
    painter.text(
        egui::pos2(x, rect.top() + 16.0),
        Align2::LEFT_TOP,
        name,
        FontId::new(15.0, semibold()),
        p.text,
    );
    let galley = painter.layout(
        desc.to_string(),
        FontId::proportional(12.0),
        p.text2,
        rect.right() - x - 16.0,
    );
    painter.galley(egui::pos2(x, rect.top() + 40.0), galley, p.text2);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
}

fn open_path(p: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let program = "xdg-open";
    std::process::Command::new(program).arg(p).spawn().map(|_| ())
}

/// Shared helper: pick a single PDF with the native file dialog.
pub(crate) fn pick_pdf(title: &str) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title(title)
        .add_filter("PDF files", &["pdf"])
        .pick_file()
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.update.poll();

        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf")))
                .collect()
        });
        if let Some(path) = dropped.into_iter().next() {
            self.drop_pdf(path);
        }

        let bg = Palette::current(ui).bg;
        // Version + "Check for updates", pinned to the bottom of Home.
        if self.page == Page::Home {
            egui::Panel::bottom("home_footer")
                .frame(egui::Frame::new().fill(bg).inner_margin(Margin {
                    left: 40,
                    right: 40,
                    top: 6,
                    bottom: 10,
                }))
                .show(ui, |ui| self.update.footer(ui));
        }
        if self.page != Page::Home && self.status.is_some() {
            egui::Panel::bottom("infobar")
                .frame(egui::Frame::new().fill(bg).inner_margin(Margin {
                    left: 40,
                    right: 40,
                    top: 8,
                    bottom: 16,
                }))
                .show(ui, |ui| self.info_bar(ui));
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(bg).inner_margin(Margin {
                left: 40,
                right: 40,
                top: 28,
                bottom: 16,
            }))
            .show(ui, |ui| match self.page {
                Page::Home => {
                    egui::ScrollArea::vertical()
                        .id_salt("home")
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.home(ui));
                }
                page => self.tool_page(ui, page),
            });

        // The update pop-up sits above everything.
        self.update.dialog(&ctx);

        // Esc returns to Home, unless the decoder is mid-search or the update dialog is open.
        if self.page != Page::Home
            && !self.decoder.running()
            && !self.update.dialog_open()
            && ctx.input(|i| i.key_pressed(egui::Key::Escape))
        {
            self.page = Page::Home;
        }
        // Keep repainting while a search runs so the live progress updates.
        if self.decoder.running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
    }
}
