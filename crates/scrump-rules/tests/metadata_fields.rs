//! Metadata exclusions must preserve credential matches, including equal bytes
//! used in a different field of the same object.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use scrump_core::{apply_hits_in_place, Chunk, ChunkOrigin, Hit};
use scrump_detect::Engine;
use scrump_rules::{default_detectors, detectors_from_path};
use std::path::Path;
use std::sync::OnceLock;

// Public npm registry integrity for @img/sharp-win32-ia32@0.35.4.
const PUBLIC_SRI: &str = "sha512-kqRsbaa5CS6KHlpxnN7WhE6vAAugXyZButpRdvDWetlv6Qv4N9WTcrWzF7tXfB9T7MsoadqdI8hmwLq6UlLvtw==";
const COSMOS: &str = "azure_cosmosdb__dbkeypattern";
const AZURE: &str = "azure_openai__azurekeypat";

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::new(default_detectors().unwrap()))
}

fn scan(text: &str) -> Vec<Hit> {
    engine().scan_chunk(&Chunk {
        bytes: text.as_bytes(),
        offset: 0,
        origin: ChunkOrigin::Raw,
    })
}

fn hits_for(text: &str, rule: &str) -> Vec<Hit> {
    scan(text)
        .into_iter()
        .filter(|hit| hit.rule_id == rule)
        .collect()
}

#[test]
fn npm_integrity_with_nested_metadata_is_not_scrubbed() {
    let input = format!(
        r#"{{"version":"0.35.4","integrity":"{PUBLIC_SRI}","dependencies":{{"other":"1.0.0"}}}}"#
    );
    let hits = scan(&input);
    assert!(hits.is_empty(), "{hits:?}");
    let mut output = input.as_bytes().to_vec();
    apply_hits_in_place(&mut output, &hits).unwrap();
    assert_eq!(output, input.as_bytes());
}

#[test]
fn explicitly_loaded_yaml_retains_its_original_pattern_behavior() {
    let detectors =
        detectors_from_path(&Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/trufflehog.yaml"))
            .unwrap()
            .into_iter()
            .filter(|detector| detector.id() == COSMOS)
            .collect();
    let input = format!(r#"{{"integrity":"{PUBLIC_SRI}"}}"#);
    let hits = Engine::new(detectors).scan_chunk(&Chunk {
        bytes: input.as_bytes(),
        offset: 0,
        origin: ChunkOrigin::Raw,
    });
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_id, COSMOS);
}

#[test]
fn equal_digest_bytes_in_a_credential_field_are_still_scrubbed() {
    let key = PUBLIC_SRI.strip_prefix("sha512-").unwrap();
    let input = format!(r#"{{"integrity":"{PUBLIC_SRI}","api_key":"{key}"}}"#);
    let hits = hits_for(&input, COSMOS);
    assert_eq!(hits.len(), 1, "{hits:?}");
    let start = input.rfind(key).unwrap();
    assert_eq!(hits[0].offset, start as u64);
    assert_eq!(hits[0].len, key.len());
    let mut output = input.as_bytes().to_vec();
    apply_hits_in_place(&mut output, &hits).unwrap();
    assert_eq!(&output[..start], &input.as_bytes()[..start]);
    assert!(output[start..start + key.len()]
        .iter()
        .all(|&byte| byte == 0));
}

#[test]
fn cosmos_keys_and_legacy_grafana_json_tokens_remain_detected() {
    let key = PUBLIC_SRI.strip_prefix("sha512-").unwrap();
    let legacy_json = format!(
        r#"{{"k":"{}","n":"secret-key","id":1}}"#,
        "0123456789abcdef".repeat(2)
    );
    assert_eq!(legacy_json.len(), 64);
    let grafana = STANDARD.encode(legacy_json);
    for text in [
        key.to_owned(),
        format!("COSMOS_KEY={key}"),
        format!(r#"{{"api_key":"{key}"}}"#),
        format!("grafana_api_key={grafana}"),
    ] {
        assert_eq!(hits_for(&text, COSMOS).len(), 1, "{text}");
    }
    assert!(engine().detectors().iter().any(|det| det.id() == COSMOS));
    assert!(engine().detectors().iter().any(|det| det.id() == AZURE));
}

#[test]
fn store_references_do_not_hide_equal_azure_keys() {
    let key = "0123456789abcdef".repeat(2);
    let input = format!(
        r#"{{"binding":"API_KEY","store_id":"{key}","secret_name":"credential","api_key":"{key}"}}"#
    );
    let hits = hits_for(&input, AZURE);
    assert_eq!(hits.len(), 1, "{hits:?}");
    let start = input.rfind(&key).unwrap();
    assert_eq!(hits[0].offset, start as u64);
    assert_eq!(hits[0].len, key.len());
    let mut output = input.as_bytes().to_vec();
    apply_hits_in_place(&mut output, &hits).unwrap();
    assert_eq!(&output[..start], &input.as_bytes()[..start]);
    assert!(output[start..start + key.len()]
        .iter()
        .all(|&byte| byte == 0));
}

#[test]
fn complete_store_bindings_allow_spacing_field_order_and_surrounding_jsonc() {
    let key = "0123456789abcdef".repeat(2);
    for input in [
        format!(r#"{{"binding":"API_KEY","store_id":"{key}","secret_name":"credential"}}"#),
        format!("// surrounding JSONC\n{{\n\"secret_name\":\"OPENAI_KEY\", \n\"store_id\" : \"{key}\",\n\"binding\":\"API_KEY\"\n}}"),
        format!(r#"{{"binding":"API_KEY","store_id":"{key}","secret_name":"value with }} and \" quotes"}}"#),
    ] {
        assert!(hits_for(&input, AZURE).is_empty(), "{input}");
    }
}

#[test]
fn ambiguous_or_incomplete_metadata_retains_the_candidate() {
    let key = "0123456789abcdef".repeat(2);
    for input in [
        format!(r#"{{"api_key":"unused","store_id":"{key}"}}"#),
        format!(r#"{{"binding":"API_KEY","store_id":"{key}","secret_name":false}}"#),
        format!(r#"{{"binding":"API_KEY","store_id":"{key}","secret_name":""}}"#),
        format!(r#"{{"binding":"API_KEY","store_id":"{key}","secret_name":"credential""#),
        format!(r#"{{"binding":"API_KEY","store_id":"{key}-suffix","secret_name":"credential"}}"#),
        format!(r#"API_KEY "store_id":"{key}""#),
    ] {
        assert_eq!(hits_for(&input, AZURE).len(), 1, "{input}");
    }
    let digest = PUBLIC_SRI.strip_prefix("sha512-").unwrap();
    for input in [
        format!(r#"{{"integrity":"{PUBLIC_SRI}""#),
        format!(r#"{{"integrity":"sha512-{digest}-suffix"}}"#),
        format!(r#"{{"integrity":"sha384-{digest}"}}"#),
        format!(r#"{{"api_key":"{PUBLIC_SRI}"}}"#),
    ] {
        assert_eq!(hits_for(&input, COSMOS).len(), 1, "{input}");
    }
}

#[test]
fn noncanonical_digest_and_missing_chunk_context_are_not_exempt() {
    // Sixty-four zero bytes encode with 'A' as the last data character.
    // 'B' has nonzero unused bits and is not a canonical SHA-512 digest.
    let bad_digest = format!("{}B==", "A".repeat(85));
    assert_eq!(
        hits_for(&format!(r#"{{"integrity":"sha512-{bad_digest}"}}"#), COSMOS).len(),
        1
    );
    let key = PUBLIC_SRI.strip_prefix("sha512-").unwrap();
    assert_eq!(hits_for(&format!("{key}\"}}"), COSMOS).len(), 1);
    let input = format!(
        r#"{{"integrity":"{PUBLIC_SRI}","padding":"{}"}}"#,
        "x".repeat(32 * 1024)
    );
    assert_eq!(hits_for(&input, COSMOS).len(), 1);
}

#[test]
fn an_earlier_object_cannot_exempt_a_later_unenclosed_candidate() {
    let key = "0123456789abcdef".repeat(2);
    let input = format!(
        r#"{{"binding":"API_KEY","store_id":"{key}","secret_name":"credential"}} API_KEY "store_id":"{key}""#
    );
    let hits = hits_for(&input, AZURE);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].offset, input.rfind(&key).unwrap() as u64);
}
