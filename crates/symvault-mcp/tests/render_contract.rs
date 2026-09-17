use sha2::{Digest, Sha256};
use symvault_mcp::render::sanitize_for_mcp;

#[test]
fn production_go_renderer_contract() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/port/mcp_render.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        assert_eq!(
            sanitize_for_mcp(input),
            case["output"].as_str().unwrap(),
            "{input:?}"
        );
    }
    let mut digest = Sha256::new();
    for c in (0..=0x10ffff).filter_map(char::from_u32) {
        digest.update(sanitize_for_mcp(&c.to_string()).as_bytes());
        digest.update([0]);
    }
    assert_eq!(
        format!("{:x}", digest.finalize()),
        fixture["scalar_digest"].as_str().unwrap()
    );
}
