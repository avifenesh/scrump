//! Helpers shared between the fixture-generator binaries.

/// Pad `bytes` up to the next multiple of `align`, NUL-filled.
pub fn pad_to(bytes: &mut Vec<u8>, align: usize) {
    let m = bytes.len() % align;
    if m != 0 {
        bytes.extend(std::iter::repeat(0u8).take(align - m));
    }
}

/// Round `n` up to the next multiple of `align`.
pub fn round_up(n: usize, align: usize) -> usize {
    let m = n % align;
    if m == 0 {
        n
    } else {
        n + (align - m)
    }
}

/// Generators for obvious-fake provider tokens. Every prefix is composed
/// from non-contiguous source fragments so secret-scanning bots reading
/// these source bytes don't recognise a leaked-token shape, while the
/// runtime output still matches scrump's detection regexes exactly.
pub mod tokens {
    fn assemble(prefix: &[&str], body: &str) -> String {
        let mut out = String::new();
        for p in prefix {
            out.push_str(p);
        }
        out.push_str(body);
        out
    }

    fn fill(s: &str, n: usize) -> String {
        let mut out = String::with_capacity(n);
        let bytes = s.as_bytes();
        while out.len() < n {
            let take = (n - out.len()).min(bytes.len());
            out.push_str(std::str::from_utf8(&bytes[..take]).unwrap());
        }
        out
    }

    pub fn ghp() -> String {
        let body = fill("TESTFAKE", 36);
        assemble(&["g", "h", "p", "_"], &body)
    }

    pub fn hf() -> String {
        let body = fill("TESTFAKE", 34);
        assemble(&["h", "f", "_"], &body)
    }

    pub fn anthropic() -> String {
        let mut s = String::new();
        for p in &["s", "k", "-", "ant", "-", "api", "03", "-"] {
            s.push_str(p);
        }
        s.push_str(&fill("TESTFAKE", 93));
        s.push_str("AA");
        s
    }

    pub fn aws() -> String {
        // AWS's documented EXAMPLE access-key id.
        let mut s = String::new();
        for p in &["A", "K", "I", "A", "IOSFODNN7EXAMPLE"] {
            s.push_str(p);
        }
        s
    }

    pub fn google() -> String {
        let body = fill("TESTFAKE", 35);
        assemble(&["A", "I", "z", "a"], &body)
    }

    pub fn slack() -> String {
        let mut s = String::new();
        for p in &["x", "ox", "b", "-"] {
            s.push_str(p);
        }
        s.push_str("0000000000-0000000000-");
        s.push_str(&fill("A", 24));
        s
    }

    pub fn ngc() -> String {
        let body = fill("TESTFAKE", 64);
        assemble(&["n", "v", "api", "-"], &body)
    }

    pub fn wandb() -> String {
        let body = fill("deadbeef", 40);
        assemble(&["w", "and", "b", "-"], &body)
    }

    /// Dispatch by name, mirroring the shell `plant_token` API.
    pub fn by_name(kind: &str) -> Option<String> {
        Some(match kind {
            "ghp" => ghp(),
            "hf" => hf(),
            "anthropic" => anthropic(),
            "aws" => aws(),
            "google" => google(),
            "slack" => slack(),
            "ngc" => ngc(),
            "wandb" => wandb(),
            _ => return None,
        })
    }
}
