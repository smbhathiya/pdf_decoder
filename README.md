# PDF Decoder

A small Windows desktop app for working with password-protected PDFs **you own** — a Rust
rewrite of the original Python/Tkinter app, built with [`eframe`/`egui`] in the same Fluent /
Windows 11 style as the sibling *Beez PDF Studio*.

> **For your own files / education only.** Use it to recover access to PDFs you are authorised
> to open.

## Features

- **Open PDF** — save a protected PDF once (with its password), then reopen it in a click. The
  app decrypts to a temporary copy and launches your PDF viewer, or saves an unlocked copy.
- **Passwords** — a wallet of reusable, named passwords, tried automatically against any PDF.
- **Decode password** — a multi-core numeric brute force for a forgotten open-password, with a
  live progress bar and ETA, plus:
  - **Owner-password detection** — a PDF that only restricts printing/editing (opens freely) has
    its restrictions stripped instantly, no cracking.
  - **Encryption analysis** — reads the PDF's `/Encrypt` revision (RC4/AES-128 vs AES-256)
    without the password and tells you whether a GPU is realistic.
  - **Known pattern** — e.g. `077???????` (`?` = unknown digit) to shrink the search space.
  - **hashcat command** — for large searches it prints a ready-to-run GPU command.

## Why this is better than the original

- **Native speed.** The brute force loads the PDF once and tests candidates directly against the
  encryption key with [`lopdf`] + [`rayon`] — no re-parsing the file per guess, across all CPU
  cores.
- **Encrypted password storage.** Passwords live in a **SQLite** database
  (`%LOCALAPPDATA%\PDF Decoder\vault.db`), and each one is sealed with the **Windows Data
  Protection API** (DPAPI) before it touches the disk — tied to your Windows account, unreadable
  on another account or PC. The original kept passwords in plain-text JSON.
- **One self-contained `.exe`** with a DirectX/Vulkan→OpenGL fallback and a crash log.

## Build & run

```powershell
cargo run            # debug
cargo build --release
cargo test           # includes an end-to-end crack of a real AES-encrypted PDF
```

## Reality check

A fully-unknown 10–12 digit password cannot be cracked on a CPU in any practical time
(billions–trillions of combinations). The app is honest about this and points you to `hashcat`
(GPU) for those cases.

[`eframe`/`egui`]: https://github.com/emilk/egui
[`lopdf`]: https://crates.io/crates/lopdf
[`rayon`]: https://crates.io/crates/rayon
