//! Print a deterministic obvious-fake token for a given provider name to
//! stdout. Used by `tests/common.sh`'s `plant_token` shell wrapper.
//!
//! Every prefix is composed by `scrump_test_fixtures::tokens` from
//! non-contiguous source fragments so the *literal* token shape never
//! appears in any checked-in file. The runtime output still matches
//! scrump's detection regexes exactly.

fn main() {
    let kind = std::env::args().nth(1).unwrap_or_default();
    match scrump_test_fixtures::tokens::by_name(&kind) {
        Some(s) => print!("{s}"),
        None => {
            eprintln!("plant-token: unknown provider: {kind:?}");
            std::process::exit(2);
        }
    }
}
