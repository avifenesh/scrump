use scrump_core::{Chunk, ChunkOrigin};
use scrump_detect::Engine;
fn main() {
    let dets = scrump_rules::default_detectors().unwrap();
    let eng = Engine::new(dets);
    let input = "pinecone_API_KEY=pcsk_T5Afk6_5qU9s3iLVFmaSaJtMat7gTHaT9fXa7ykiBk7iz4uUMuLGLemkdutTgwJevYhqtn";
    let chunk = Chunk {
        bytes: input.as_bytes(),
        offset: 0,
        origin: ChunkOrigin::Raw,
    };
    let hits = eng.scan_chunk(&chunk);
    for h in &hits {
        let from = h.offset as usize;
        let to = from + h.len;
        let m = input.get(from..to).unwrap_or("?");
        if h.rule_id.starts_with("pinecone") {
            println!(
                "HIT: rule={} offset={} len={} match={:?}",
                h.rule_id, h.offset, h.len, m
            );
        }
    }
}
