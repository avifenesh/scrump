//! Generate a tiny classic-pcap file with one synthetic Ethernet+IP+TCP
//! packet whose payload contains the planted strings concatenated with
//! `\r\n` (mimicking an HTTP request leak).
//!
//! Usage: `make-pcap <output.pcap> <planted_str_1> [planted_str_2 ...]`

use byteorder::{LittleEndian, WriteBytesExt};

const PCAP_LE_USEC: u32 = 0xa1b2_c3d4;
const LINKTYPE_RAW: u32 = 101; // raw IP; avoids the need for Ethernet framing

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, planted) = match args.as_slice() {
        [out, rest @ ..] if !rest.is_empty() => (out.clone(), rest.to_vec()),
        _ => {
            eprintln!("usage: make-pcap <out> <planted_str> [more...]");
            std::process::exit(2);
        }
    };

    // Build the packet payload as an HTTP-ish blob — no need to be real
    // wire-format; scrump scans the bytes regardless. (The pcap parser
    // only cares about record framing.)
    let mut payload = Vec::<u8>::new();
    payload.extend_from_slice(b"GET /api HTTP/1.1\r\n");
    payload.extend_from_slice(b"Host: example.com\r\n");
    for s in &planted {
        payload.extend_from_slice(b"Authorization: Bearer ");
        payload.extend_from_slice(s.as_bytes());
        payload.extend_from_slice(b"\r\n");
    }
    payload.extend_from_slice(b"\r\n");

    let mut f = Vec::new();
    // File header (24 bytes).
    f.write_u32::<LittleEndian>(PCAP_LE_USEC).unwrap();
    f.write_u16::<LittleEndian>(2).unwrap(); // major
    f.write_u16::<LittleEndian>(4).unwrap(); // minor
    f.write_i32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(65535).unwrap();
    f.write_u32::<LittleEndian>(LINKTYPE_RAW).unwrap();
    // Packet record (16-byte header + payload).
    f.write_u32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(payload.len() as u32).unwrap();
    f.write_u32::<LittleEndian>(payload.len() as u32).unwrap();
    f.extend_from_slice(&payload);

    let tmp = format!("{out}.tmp");
    std::fs::write(&tmp, &f).expect("write");
    std::fs::rename(&tmp, &out).expect("rename");
    eprintln!(
        "wrote {out} ({} bytes, payload @ 0x28+{})",
        f.len(),
        payload.len()
    );
}
