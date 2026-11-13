//! PDF password engine: inspect how a file is locked, strip owner-only restrictions,
//! read the encryption strength, and run a multi-core numeric brute force for a forgotten
//! open-password. A Rust rewrite of the reference app's `core/engine.py`, using `lopdf` for the
//! crypto and `rayon` for the search (load the file once, then test candidates in parallel with
//! no re-parsing - much faster than opening the PDF per guess).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use lopdf::Document;
use lopdf::encryption::PasswordAlgorithm;
use rayon::prelude::*;

use crate::progress::{Cancelled, Progress};

/// How a PDF is locked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockState {
    /// Not encrypted at all.
    Plain,
    /// Opens freely but restricts printing/editing (owner password only) - strippable instantly.
    Owner,
    /// Needs a password just to open - requires a brute force.
    User,
}

/// Classify how a PDF is locked, without brute forcing.
pub fn open_state(path: &Path) -> Result<LockState> {
    let doc = Document::load(path).with_context(|| format!("Could not read {}", path.display()))?;
    // `load` tries the empty user password. If a file carried encryption and opened anyway,
    // it only had an owner (permissions) password; lopdf then clears `is_encrypted`, so the
    // "was it encrypted" flag is what distinguishes owner-only from a truly plain file.
    Ok(if doc.was_encrypted() {
        LockState::Owner
    } else if doc.is_encrypted() {
        LockState::User
    } else {
        LockState::Plain
    })
}

/// Save an unrestricted copy of an owner-password-only PDF (no cracking needed).
pub fn strip_restrictions(path: &Path, out: &Path) -> Result<()> {
    let mut doc =
        Document::load(path).with_context(|| format!("Could not read {}", path.display()))?;
    if doc.is_encrypted() {
        // Owner-only files are already decrypted by `load`; dropping the state saves them plain.
        doc.decrypt("").ok();
    }
    doc.encryption_state = None;
    save_plain(&mut doc, out)
}

/// Decrypt `path` with `password` and save an unlocked copy to `out`.
pub fn save_unlocked(path: &Path, password: &str, out: &Path) -> Result<()> {
    let mut doc = Document::load_with_password(path, password)
        .map_err(|e| anyhow!("Could not open {} - wrong password? ({e})", path.display()))?;
    if doc.is_encrypted() {
        doc.decrypt(password)
            .map_err(|e| anyhow!("Wrong password ({e})"))?;
    }
    doc.encryption_state = None;
    save_plain(&mut doc, out)
}

fn save_plain(doc: &mut Document, out: &Path) -> Result<()> {
    doc.save(out)
        .with_context(|| format!("Could not save {}", out.display()))?;
    Ok(())
}

/// Does `password` open this PDF? (Empty string = no user password.)
pub fn verify_password(path: &Path, password: &str) -> bool {
    Document::load_with_password(path, password).is_ok()
}

/// Whether the PDF needs a password just to open.
pub fn needs_password(path: &Path) -> bool {
    !verify_password(path, "")
}

// --- Encryption analysis -----------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Encryption {
    pub revision: i64,
    pub version: i64,
    /// AES-256 (R5/R6): GPU-resistant, slow even on hardware.
    pub strong: bool,
    pub hashcat_mode: Option<u32>,
    pub label: String,
}

/// Read the `/Encrypt` revision and version without the password (the dictionary is stored
/// unencrypted). Works on a locked file.
pub fn analyze_encryption(path: &Path) -> Result<Encryption> {
    let doc = Document::load(path).with_context(|| format!("Could not read {}", path.display()))?;
    let enc = doc
        .get_encrypted()
        .map_err(|_| anyhow!("This PDF is not encrypted"))?;
    let revision = enc.get(b"R").and_then(|o| o.as_i64()).unwrap_or(-1);
    let version = enc.get(b"V").and_then(|o| o.as_i64()).unwrap_or(-1);
    let strong = revision >= 5;
    let hashcat_mode = match revision {
        2 => Some(10400),
        3 | 4 => Some(10500),
        5 | 6 => Some(10700),
        _ => None,
    };
    let label = if revision < 0 {
        "unknown / not standard-encrypted".to_string()
    } else if strong {
        format!("AES-256 (R{revision}) - GPU-resistant, slow to crack")
    } else {
        format!("RC4/AES-128 (R{revision}) - fast to crack on a GPU")
    };
    Ok(Encryption {
        revision,
        version,
        strong,
        hashcat_mode,
        label,
    })
}

/// A ready-to-run hashcat command for a numeric brute force of this PDF.
pub fn hashcat_command(path: &Path, mode: Option<u32>, min_len: u32, max_len: u32) -> String {
    let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let file = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file.pdf");
    let mode_str = mode
        .map(|m| m.to_string())
        .unwrap_or_else(|| "<mode>".into());
    let mask = "?d".repeat(max_len as usize);
    format!(
        "# 1) Extract the hash (needs John the Ripper's pdf2john):\n\
         pdf2john {file} > {name}.hash\n\
         # 2) Brute force digits {min_len}-{max_len} on GPU:\n\
         hashcat -m {mode_str} -a 3 {name}.hash \
         --increment --increment-min {min_len} --increment-max {max_len} {mask}"
    )
}

// --- Candidate space ---------------------------------------------------------------------

/// Total number of candidates for a mask, or across the length range.
pub fn keyspace(min_len: u32, max_len: u32, mask: &str) -> u128 {
    if !mask.is_empty() {
        return 10u128.pow(mask.matches('?').count() as u32);
    }
    (min_len..=max_len).map(|n| 10u128.pow(n)).sum()
}

/// A validated search space: either a digit-length range or a fixed mask like `077???????`.
enum Space {
    Range {
        min: u32,
        max: u32,
    },
    Mask {
        template: Vec<u8>,
        slots: Vec<usize>,
    },
}

impl Space {
    fn build(min_len: u32, max_len: u32, mask: &str) -> Result<Self> {
        if !mask.is_empty() {
            if mask.bytes().any(|b| !(b.is_ascii_digit() || b == b'?')) {
                bail!("A pattern may contain only digits and '?'.");
            }
            let template = mask.bytes().collect::<Vec<u8>>();
            let slots = template
                .iter()
                .enumerate()
                .filter(|&(_, &b)| b == b'?')
                .map(|(i, _)| i)
                .collect();
            Ok(Space::Mask { template, slots })
        } else {
            if min_len < 1 || max_len < min_len || max_len > 18 {
                bail!("Need 1 ≤ min ≤ max ≤ 18 digits.");
            }
            Ok(Space::Range {
                min: min_len,
                max: max_len,
            })
        }
    }
}

/// Write the `i`-th candidate of a `len`-digit range into `buf` (zero-padded, shortest first).
fn digits_into(buf: &mut Vec<u8>, len: u32, mut i: u64) {
    buf.clear();
    buf.resize(len as usize, b'0');
    let mut pos = len as usize;
    while pos > 0 {
        pos -= 1;
        buf[pos] = b'0' + (i % 10) as u8;
        i /= 10;
    }
}

/// Write the `i`-th candidate of a mask into `template` at its `slots`.
fn mask_into(template: &mut [u8], slots: &[usize], mut i: u64) {
    for &slot in slots.iter().rev() {
        template[slot] = b'0' + (i % 10) as u8;
        i /= 10;
    }
}

// --- The search --------------------------------------------------------------------------

/// Candidates handed to the thread pool per batch (keeps progress/cancel responsive).
const BATCH: u64 = 50_000;

#[derive(Clone, Debug)]
pub enum Found {
    /// The open-password was recovered.
    Password(String),
    /// Searched the whole space without a match.
    NotFound,
}

/// Run the multi-core numeric brute force. Reports progress and stops promptly on cancel.
/// Returns the password, or `NotFound`. `total_tried` is written for the final summary.
pub fn run_search(
    path: &Path,
    min_len: u32,
    max_len: u32,
    mask: &str,
    pr: &Progress,
) -> Result<Found> {
    let space = Space::build(min_len, max_len, mask)?;
    let doc = Document::load(path).with_context(|| format!("Could not read {}", path.display()))?;
    if !doc.is_encrypted() {
        return Ok(Found::NotFound); // caller handles plain/owner before getting here
    }
    let algo = PasswordAlgorithm::try_from(&doc)
        .map_err(|e| anyhow!("Unsupported or missing encryption: {e}"))?;

    let ks = keyspace(min_len, max_len, mask);
    let start = Instant::now();
    let stop = AtomicBool::new(false);
    let mut tried: u128 = 0;

    // Each length (or the single mask) is swept in parallel, batch by batch.
    let lengths: Vec<(u32, u64)> = match &space {
        Space::Range { min, max } => (*min..=*max).map(|n| (n, 10u64.pow(n))).collect(),
        Space::Mask { slots, .. } => vec![(0, 10u64.pow(slots.len() as u32))],
    };

    for (len, count) in lengths {
        let mut base = 0u64;
        while base < count {
            pr.check()?;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let end = (base + BATCH).min(count);
            let hit = (base..end).into_par_iter().find_map_any(|i| {
                if stop.load(Ordering::Relaxed) {
                    return None;
                }
                let mut buf;
                let candidate: &[u8] = match &space {
                    Space::Range { .. } => {
                        buf = Vec::new();
                        digits_into(&mut buf, len, i);
                        &buf
                    }
                    Space::Mask { template, slots } => {
                        buf = template.clone();
                        mask_into(&mut buf, slots, i);
                        &buf
                    }
                };
                match algo.authenticate_user_password(&doc, candidate) {
                    Ok(()) => Some(String::from_utf8_lossy(candidate).into_owned()),
                    Err(_) => None,
                }
            });

            tried += (end - base) as u128;
            let frac = if ks == 0 {
                1.0
            } else {
                tried as f32 / ks as f32
            };
            let elapsed = start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                tried as f64 / elapsed
            } else {
                0.0
            };
            let eta = if rate > 0.0 {
                (ks.saturating_sub(tried)) as f64 / rate
            } else {
                0.0
            };
            pr.set(
                frac,
                format!(
                    "{} tried · {:.0}/s · ETA {}",
                    group(tried),
                    rate,
                    fmt_time(eta)
                ),
            );

            if let Some(pw) = hit {
                stop.store(true, Ordering::Relaxed);
                return Ok(Found::Password(pw));
            }
            base = end;
        }
    }
    let _ = Cancelled; // keep the import meaningful if cancel never fires
    Ok(Found::NotFound)
}

/// Format a duration as `H:MM:SS` (or `M:SS` under an hour), or `∞` when astronomically large.
pub fn fmt_time(seconds: f64) -> String {
    if !seconds.is_finite() || seconds > 3.15e9 {
        return "∞".into();
    }
    let s = seconds.max(0.0) as u64;
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m}:{sec:02}")
    }
}

/// Group a number with thin separators, e.g. `1,234,567`.
pub fn group(n: u128) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// A rough multi-core CPU estimate (seconds) for the given keyspace, for the "too slow" warning.
pub fn rough_cpu_seconds(ks: u128, workers: usize) -> f64 {
    let rate = 40_000.0 * workers.max(1) as f64; // conservative authenticate() rate per core
    ks as f64 / rate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyspace_math() {
        assert_eq!(keyspace(1, 3, ""), 10 + 100 + 1000);
        assert_eq!(keyspace(1, 6, "077???????"), 10u128.pow(7));
    }

    #[test]
    fn digit_candidates() {
        let mut buf = Vec::new();
        digits_into(&mut buf, 4, 42);
        assert_eq!(&buf, b"0042");
        digits_into(&mut buf, 2, 7);
        assert_eq!(&buf, b"07");
    }

    #[test]
    fn mask_candidates() {
        let space = Space::build(1, 6, "07???").unwrap();
        if let Space::Mask { template, slots } = space {
            let mut t = template.clone();
            mask_into(&mut t, &slots, 123);
            assert_eq!(&t, b"07123");
        } else {
            panic!("expected a mask");
        }
    }

    #[test]
    fn bad_mask_rejected() {
        assert!(Space::build(1, 6, "07a").is_err());
    }

    #[test]
    fn time_formatting() {
        assert_eq!(fmt_time(65.0), "1:05");
        assert_eq!(fmt_time(3661.0), "1:01:01");
        assert_eq!(fmt_time(f64::INFINITY), "∞");
    }

    // --- End-to-end: build a real encrypted PDF, then recover its password ---------------

    use std::collections::BTreeMap;
    use std::sync::Arc;

    use lopdf::encryption::crypt_filters::{Aes128CryptFilter, CryptFilter};
    use lopdf::{
        EncryptionState, EncryptionVersion, Object, Permissions, Stream, StringFormat, dictionary,
    };

    /// Write a one-page PDF to `path`, encrypted so `user_pw` is needed to open it.
    fn make_protected(path: &Path, user_pw: &str, owner_pw: &str) {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let content = b"BT /F1 24 Tf 72 720 Td (hello) Tj ET".to_vec();
        let c = doc.add_object(Stream::new(dictionary! {}, content));
        let page = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => c,
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page)], "Count" => 1i64,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            }),
        );
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let id: Vec<u8> = (0u8..16).collect();
        doc.trailer.set(
            "ID",
            vec![
                Object::String(id.clone(), StringFormat::Hexadecimal),
                Object::String(id, StringFormat::Hexadecimal),
            ],
        );

        let filter: Arc<dyn CryptFilter> = Arc::new(Aes128CryptFilter);
        let version = EncryptionVersion::V4 {
            document: &doc,
            encrypt_metadata: true,
            crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), filter)]),
            stream_filter: b"StdCF".to_vec(),
            string_filter: b"StdCF".to_vec(),
            owner_password: owner_pw,
            user_password: user_pw,
            permissions: Permissions::all(),
        };
        let state = EncryptionState::try_from(version).unwrap();
        doc.encrypt(&state).unwrap();
        doc.save(path).unwrap();
    }

    #[test]
    fn recovers_a_numeric_open_password() {
        let dir = std::env::temp_dir().join("pdf_decorder_test_user");
        let _ = std::fs::create_dir_all(&dir);
        let pdf = dir.join("locked.pdf");
        make_protected(&pdf, "0042", "ownersecret");

        assert_eq!(open_state(&pdf).unwrap(), LockState::User);
        assert!(verify_password(&pdf, "0042"));
        assert!(!verify_password(&pdf, "0043"));
        assert!(needs_password(&pdf));

        let found = run_search(&pdf, 1, 4, "", &Progress::default()).unwrap();
        match found {
            Found::Password(pw) => assert_eq!(pw, "0042"),
            Found::NotFound => panic!("should have found 0042"),
        }

        // And a known-pattern mask narrows it immediately.
        let found = run_search(&pdf, 1, 6, "00??", &Progress::default()).unwrap();
        assert!(matches!(found, Found::Password(p) if p == "0042"));

        // Decrypting with the recovered password produces an openable plain PDF.
        let out = dir.join("unlocked.pdf");
        save_unlocked(&pdf, "0042", &out).unwrap();
        assert_eq!(open_state(&out).unwrap(), LockState::Plain);
    }

    #[test]
    fn owner_only_is_stripped_without_cracking() {
        let dir = std::env::temp_dir().join("pdf_decorder_test_owner");
        let _ = std::fs::create_dir_all(&dir);
        let pdf = dir.join("owner.pdf");
        // Empty user password => opens freely; only the owner password restricts it.
        make_protected(&pdf, "", "ownersecret");

        assert_eq!(open_state(&pdf).unwrap(), LockState::Owner);
        let out = dir.join("owner_unlocked.pdf");
        strip_restrictions(&pdf, &out).unwrap();
        assert_eq!(open_state(&out).unwrap(), LockState::Plain);
    }
}
