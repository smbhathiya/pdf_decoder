//! Saved PDFs and the password wallet, stored in a SQLite database in
//! `%LOCALAPPDATA%\PDF Decoder\vault.db`.
//!
//! Unlike the reference app (plain-text JSON in the home folder), every stored password is
//! sealed with the Windows Data Protection API ([`crate::secret`]) before it touches the disk,
//! so the database is useless to anyone not logged in as this Windows user.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rusqlite::Connection;

use crate::engine::verify_password;
use crate::secret;
use crate::startup;

/// A saved PDF the user can reopen in one click.
#[derive(Clone, Debug)]
pub struct Entry {
    pub id: i64,
    pub label: String,
    pub path: String,
    pub password: String,
    pub added: String,
}

/// A reusable named password in the wallet.
#[derive(Clone, Debug)]
pub struct Password {
    pub id: i64,
    pub name: String,
    pub password: String,
}

pub struct Vault {
    conn: Connection,
}

fn db_path() -> PathBuf {
    startup::data_dir().join("vault.db")
}

fn now() -> String {
    // A plain local-ish timestamp from the system clock, YYYY-MM-DD HH:MM (UTC).
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", rem / 3600, rem % 3600 / 60)
}

impl Vault {
    /// Open (creating if needed) the vault database.
    pub fn open() -> Result<Self> {
        let conn = Connection::open(db_path()).context("Could not open the password database")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                 id       INTEGER PRIMARY KEY,
                 label    TEXT NOT NULL,
                 path     TEXT NOT NULL UNIQUE,
                 password BLOB NOT NULL,
                 added    TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS passwords (
                 id       INTEGER PRIMARY KEY,
                 name     TEXT NOT NULL,
                 password BLOB NOT NULL,
                 added    TEXT NOT NULL
             );",
        )
        .context("Could not set up the password database")?;
        Ok(Self { conn })
    }

    // --- Saved PDFs ----------------------------------------------------------------------

    pub fn entries(&self) -> Result<Vec<Entry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, label, path, password, added FROM entries ORDER BY added DESC")?;
        let rows = stmt.query_map([], |r| {
            let sealed: Vec<u8> = r.get(3)?;
            Ok(Entry {
                id: r.get(0)?,
                label: r.get(1)?,
                path: r.get(2)?,
                password: secret::open(&sealed),
                added: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Verify `password` opens `path`, then save (or update) the entry.
    pub fn add_entry(&self, path: &Path, password: &str, label: &str) -> Result<()> {
        if !verify_password(path, password) {
            bail!("That password does not open this PDF.");
        }
        let label = if label.trim().is_empty() {
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("PDF")
                .to_string()
        } else {
            label.trim().to_string()
        };
        let abs = std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned();
        self.conn.execute(
            "INSERT INTO entries (label, path, password, added) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(path) DO UPDATE SET label = ?1, password = ?3, added = ?4",
            rusqlite::params![label, abs, secret::seal(password), now()],
        )?;
        Ok(())
    }

    pub fn remove_entry(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM entries WHERE id = ?1", [id])?;
        Ok(())
    }

    // --- Password wallet -----------------------------------------------------------------

    pub fn passwords(&self) -> Result<Vec<Password>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, password FROM passwords ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            let sealed: Vec<u8> = r.get(2)?;
            Ok(Password {
                id: r.get(0)?,
                name: r.get(1)?,
                password: secret::open(&sealed),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Add a named password. Rejects a blank password or an exact duplicate.
    pub fn add_password(&self, name: &str, password: &str) -> Result<()> {
        if password.is_empty() {
            bail!("Enter a password first.");
        }
        let name = if name.trim().is_empty() {
            "Unnamed".to_string()
        } else {
            name.trim().to_string()
        };
        if self.passwords()?.iter().any(|p| p.password == password) {
            bail!("That password is already in the wallet.");
        }
        self.conn.execute(
            "INSERT INTO passwords (name, password, added) VALUES (?1, ?2, ?3)",
            rusqlite::params![name, secret::seal(password), now()],
        )?;
        Ok(())
    }

    pub fn remove_password(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM passwords WHERE id = ?1", [id])?;
        Ok(())
    }

    /// The first wallet password that opens `path`, or `None`. The empty password (owner-only /
    /// no open password) is tried last and reported with a friendly name.
    pub fn find_match(&self, path: &Path) -> Result<Option<Password>> {
        for p in self.passwords()? {
            if verify_password(path, &p.password) {
                return Ok(Some(p));
            }
        }
        if verify_password(path, "") {
            return Ok(Some(Password {
                id: -1,
                name: "(no password needed)".into(),
                password: String::new(),
            }));
        }
        Ok(None)
    }
}
