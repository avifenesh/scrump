//! Build a small SQLite database with planted token rows.
//!
//! Usage: `make-sqlite <output.sqlite> <name1=value1> [<name2=value2> ...]`

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, pairs) = match args.as_slice() {
        [out, rest @ ..] if !rest.is_empty() => (out.clone(), rest.to_vec()),
        _ => {
            eprintln!("usage: make-sqlite <out> <name=value> [more...]");
            std::process::exit(2);
        }
    };
    let _ = std::fs::remove_file(&out);
    let conn = rusqlite::Connection::open(&out).expect("open");
    conn.execute_batch(
        "CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT); \
         CREATE TABLE clean (n INTEGER, s TEXT);",
    )
    .expect("schema");
    for p in &pairs {
        let mut it = p.splitn(2, '=');
        let name = it.next().unwrap_or("");
        let value = it.next().unwrap_or("");
        conn.execute(
            "INSERT INTO secrets (name, value) VALUES (?1, ?2)",
            rusqlite::params![name, value],
        )
        .expect("insert");
    }
    conn.execute("INSERT INTO clean (n, s) VALUES (1, 'no secrets here')", [])
        .expect("insert clean");
    conn.close().expect("close");
    eprintln!("wrote {out}");
}
