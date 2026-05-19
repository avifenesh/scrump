//! SQLite database handler.
//!
//! Strategy:
//!   * detect via the canonical "SQLite format 3\0" header (16 bytes);
//!   * copy the source file to a sibling temp path and open the temp;
//!   * collect every TEXT/BLOB cell across every user table into a
//!     contiguous, monotonically-numbered offset space that the engine
//!     scans through `chunks()`;
//!   * apply hits by issuing `UPDATE … WHERE rowid = ?` per affected
//!     cell; commit; VACUUM (rewriting the file so freed page-slack
//!     containing the old secret bytes is purged); close the connection;
//!   * `to_bytes` returns the post-VACUUM file contents.
//!
//! After scrubbing, the database remains structurally valid: schema is
//! untouched, all rows still exist, all row identities are preserved,
//! and the file passes `sqlite3 db ".schema"` and ".tables".
//!
//! Trade-off: ZeroFill replaces the matched substring with NUL bytes,
//! which lands as raw bytes in the column. SQLite consumers that
//! expected pure UTF-8 may render that oddly — but the secret is
//! definitively gone.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use scrump_core::{Chunk, ChunkOrigin, Format, Handler, Hit, Replacement, Result, ScrumpError};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

struct Cell {
    table: String,
    col: String,
    rowid: i64,
    value: Vec<u8>,
    base: u64,
}

pub struct SqliteDb {
    src_bytes: Vec<u8>,
    tmp_path: PathBuf,
    conn: Option<rusqlite::Connection>,
    cells: Vec<Cell>,
    applied: bool,
}

impl Drop for SqliteDb {
    fn drop(&mut self) {
        if let Some(c) = self.conn.take() {
            let _ = c.close();
        }
        let _ = std::fs::remove_file(&self.tmp_path);
    }
}

impl SqliteDb {
    pub fn open_path(path: &Path) -> Result<Self> {
        let src_bytes = std::fs::read(path)?;
        Self::from_bytes_inner(src_bytes, Some(path))
    }

    pub fn from_bytes(bytes: Vec<u8>, hint: Option<&Path>) -> Result<Self> {
        Self::from_bytes_inner(bytes, hint)
    }

    fn from_bytes_inner(src_bytes: Vec<u8>, hint: Option<&Path>) -> Result<Self> {
        if src_bytes.len() < SQLITE_MAGIC.len() || &src_bytes[..SQLITE_MAGIC.len()] != SQLITE_MAGIC
        {
            return Err(ScrumpError::InvalidFile(
                "not a SQLite database (missing 'SQLite format 3' magic)".into(),
            ));
        }

        // Materialise to a temp file so we can use rusqlite on it without
        // mutating the caller's source. The dir component preserves the
        // original parent if we know it; otherwise falls back to /tmp.
        let tmp = make_tmp_path(hint)?;
        std::fs::write(&tmp, &src_bytes)?;
        let conn = rusqlite::Connection::open(&tmp).map_err(sqlerr)?;
        // Use DELETE journal mode so all changes go straight into the main DB
        // file (no separate .wal/.shm files we'd have to handle).
        conn.pragma_update(None, "journal_mode", "DELETE")
            .map_err(sqlerr)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(sqlerr)?;

        let cells = collect_text_cells(&conn)?;

        Ok(Self {
            src_bytes,
            tmp_path: tmp,
            conn: Some(conn),
            cells,
            applied: false,
        })
    }
}

fn collect_text_cells(conn: &rusqlite::Connection) -> Result<Vec<Cell>> {
    // Walk user tables.
    let mut tables: Vec<String> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .map_err(sqlerr)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlerr)?;
        for r in rows {
            tables.push(r.map_err(sqlerr)?);
        }
    }

    let mut cells = Vec::new();
    let mut base: u64 = 0;
    for table in &tables {
        // Discover column names + types.
        let mut col_stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .map_err(sqlerr)?;
        let cols: Vec<(String, String)> = col_stmt
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .map_err(sqlerr)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sqlerr)?;

        // Filter to text-ish columns (TEXT, CHAR, VARCHAR, CLOB, BLOB).
        let text_cols: Vec<String> = cols
            .into_iter()
            .filter(|(_, ty)| {
                let u = ty.to_uppercase();
                u.contains("TEXT")
                    || u.contains("CHAR")
                    || u.contains("CLOB")
                    || u.contains("BLOB")
                    || u.is_empty() // SQLite type affinity: declared "" -> any
            })
            .map(|(name, _)| name)
            .collect();

        for col in &text_cols {
            let sql = format!(
                "SELECT rowid, \"{col}\" FROM \"{table}\" WHERE typeof(\"{col}\") IN ('text', 'blob')"
            );
            let mut stmt = conn.prepare(&sql).map_err(sqlerr)?;
            let rows = stmt
                .query_map([], |r| {
                    let rowid: i64 = r.get(0)?;
                    let bytes: Vec<u8> = match r.get_ref(1)? {
                        rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) => {
                            b.to_vec()
                        }
                        _ => Vec::new(),
                    };
                    Ok((rowid, bytes))
                })
                .map_err(sqlerr)?;
            for r in rows {
                let (rowid, bytes) = r.map_err(sqlerr)?;
                if bytes.is_empty() {
                    continue;
                }
                let len = bytes.len() as u64;
                cells.push(Cell {
                    table: table.clone(),
                    col: col.clone(),
                    rowid,
                    value: bytes,
                    base,
                });
                base += len;
            }
        }
    }
    Ok(cells)
}

impl Format for SqliteDb {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a> {
        let it = self.cells.iter().map(|c| Chunk {
            bytes: &c.value,
            offset: c.base,
            origin: ChunkOrigin::StringTable(format!("{}.{}", c.table, c.col)),
        });
        Box::new(it)
    }

    fn apply(&mut self, hits: &[Hit]) -> Result<()> {
        if hits.is_empty() {
            return Ok(());
        }
        let conn = self
            .conn
            .as_ref()
            .ok_or_else(|| ScrumpError::Other("sqlite: connection already closed".into()))?;

        // Build new values per cell (multiple hits per cell allowed).
        let mut updates: HashMap<usize, Vec<u8>> = HashMap::new();
        for h in hits {
            let cell_idx = self
                .cells
                .iter()
                .position(|c| {
                    h.offset >= c.base
                        && (h.offset + h.len as u64) <= (c.base + c.value.len() as u64)
                })
                .ok_or_else(|| {
                    ScrumpError::RedactionFailed(format!(
                        "sqlite: hit at offset {} not in any cell",
                        h.offset
                    ))
                })?;
            let local_off = (h.offset - self.cells[cell_idx].base) as usize;
            let local_end = local_off + h.len;
            let new_value = updates
                .entry(cell_idx)
                .or_insert_with(|| self.cells[cell_idx].value.clone());
            match &h.replacement {
                Replacement::ZeroFill => {
                    for b in &mut new_value[local_off..local_end] {
                        *b = 0;
                    }
                }
                Replacement::Pattern(p) => {
                    if p.is_empty() {
                        return Err(ScrumpError::RedactionFailed("empty pattern".into()));
                    }
                    for (i, b) in new_value[local_off..local_end].iter_mut().enumerate() {
                        *b = p[i % p.len()];
                    }
                }
                Replacement::Drop => {
                    return Err(ScrumpError::RedactionFailed(
                        "Drop replacement not supported for SQLite cells".into(),
                    ));
                }
            }
        }

        let tx = conn.unchecked_transaction().map_err(sqlerr)?;
        for (idx, new_value) in &updates {
            let cell = &self.cells[*idx];
            let sql = format!(
                "UPDATE \"{}\" SET \"{}\" = ?1 WHERE rowid = ?2",
                cell.table, cell.col
            );
            tx.execute(&sql, rusqlite::params![&new_value[..], cell.rowid])
                .map_err(sqlerr)?;
        }
        tx.commit().map_err(sqlerr)?;

        // VACUUM rewrites the database file, purging freed page slack.
        conn.execute("VACUUM", []).map_err(sqlerr)?;

        // Close the connection so the file is unlocked and fully flushed.
        let conn = self.conn.take().unwrap();
        conn.close().map_err(|(_, e)| sqlerr(e))?;
        self.applied = true;

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        if !self.applied {
            return Ok(self.src_bytes.clone());
        }
        Ok(std::fs::read(&self.tmp_path)?)
    }
}

// ---- helpers ---------------------------------------------------------------

fn sqlerr(e: rusqlite::Error) -> ScrumpError {
    ScrumpError::Other(format!("sqlite: {e}"))
}

fn make_tmp_path(hint: Option<&Path>) -> Result<PathBuf> {
    let parent = std::env::temp_dir();
    let stem = hint
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("sqlite");
    let unique = format!(
        "scrump-sqlite-{}-{}-{stem}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    Ok(parent.join(unique))
}

// ---- handler registration --------------------------------------------------

fn detect(head: &[u8], _path: &Path) -> bool {
    head.len() >= SQLITE_MAGIC.len() && &head[..SQLITE_MAGIC.len()] == SQLITE_MAGIC
}

fn open_path(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(SqliteDb::open_path(path)?))
}

fn open_bytes(bytes: Vec<u8>, hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(SqliteDb::from_bytes(bytes, hint)?))
}

pub fn handler() -> Handler {
    Handler {
        name: "sqlite",
        detect,
        open_path,
        open_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db(planted: &str) -> (PathBuf, Vec<u8>) {
        let p = make_tmp_path(None).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        conn.execute_batch("CREATE TABLE creds (id INTEGER PRIMARY KEY, name TEXT, value TEXT);")
            .unwrap();
        conn.execute(
            "INSERT INTO creds (name, value) VALUES ('GH', ?1)",
            rusqlite::params![planted],
        )
        .unwrap();
        conn.close().unwrap();
        let bytes = std::fs::read(&p).unwrap();
        (p, bytes)
    }

    #[test]
    fn detect_recognises_magic() {
        assert!(detect(b"SQLite format 3\0xxx", Path::new("/x/a")));
        assert!(!detect(b"notdb", Path::new("/x/a")));
    }

    #[test]
    fn scan_finds_text_cells() {
        let token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (p, _) = fresh_db(token);
        let db = SqliteDb::open_path(&p).unwrap();
        let chunks: Vec<_> = db.chunks().collect();
        // At least one chunk (the value cell). The 'GH' name cell is also TEXT.
        assert!(
            chunks.len() >= 2,
            "expected ≥2 chunks, got {}",
            chunks.len()
        );
        let saw_token = chunks
            .iter()
            .any(|c| c.bytes.windows(token.len()).any(|w| w == token.as_bytes()));
        assert!(saw_token);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn apply_zero_fills_cell_and_persists() {
        let token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (p, _) = fresh_db(token);
        let mut db = SqliteDb::open_path(&p).unwrap();
        // Find the cell containing the token, build a Hit.
        let cell_chunk = db
            .cells
            .iter()
            .find(|c| c.value.windows(token.len()).any(|w| w == token.as_bytes()))
            .unwrap();
        let rel = cell_chunk
            .value
            .windows(token.len())
            .position(|w| w == token.as_bytes())
            .unwrap() as u64;
        let abs = cell_chunk.base + rel;
        db.apply(&[Hit {
            offset: abs,
            len: token.len(),
            rule_id: "test".into(),
            verified: None,
            replacement: Replacement::ZeroFill,
            origin: ChunkOrigin::StringTable("creds.value".into()),
        }])
        .unwrap();
        let out = db.to_bytes().unwrap();
        // Token absent from raw file bytes.
        assert!(!out.windows(token.len()).any(|w| w == token.as_bytes()));
        // SQLite header magic intact.
        assert_eq!(&out[..16], b"SQLite format 3\0");
        std::fs::remove_file(&p).ok();
    }
}
