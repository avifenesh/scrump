//! Sanity-check that a SQLite file is still openable and report row counts
//! for the `secrets` and `clean` tables. Exits 0 on success.
//!
//! Usage: `sqlite-check <db>`

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [p] => p.clone(),
        _ => {
            eprintln!("usage: sqlite-check <db>");
            std::process::exit(2);
        }
    };

    let conn = rusqlite::Connection::open(&path).expect("open");
    // .schema-style: list user tables.
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .expect("prepare master");
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .collect::<std::result::Result<_, _>>()
        .expect("collect");
    drop(stmt);
    let mut bad = 0;
    for name in &names {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |r| {
                r.get(0)
            })
            .expect("count");
        eprintln!("{name}: {count} rows");
        if count < 0 {
            bad += 1;
        }
    }
    if bad > 0 {
        std::process::exit(1);
    }
    conn.close().expect("close");
}
