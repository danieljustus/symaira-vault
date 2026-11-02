//! TEMPORARY drift guard (removed with the Go tree in the RUST-015 delete step).
//!
//! The built-in API templates are compiled into `symvault-mcp` from
//! `assets/apitemplates/`. The Go tree still embeds its own copy
//! (`internal/mcp/apitemplates/builtin/`, `//go:embed` cannot point outside its
//! package). Until the Go tree is deleted both copies must stay byte-identical;
//! once `internal/` is gone the crate-local assets are the only source of truth
//! and this check has nothing left to compare.

use std::fs;
use std::path::Path;

#[test]
fn crate_local_templates_match_remaining_go_copy_until_go_deletion() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let assets = crate_dir.join("assets/apitemplates");
    let go_copy = crate_dir.join("../../internal/mcp/apitemplates/builtin");

    let mut names: Vec<String> = fs::read_dir(&assets)
        .expect("crate-local template assets exist")
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 17, "expected the 17 built-in templates");
    assert!(names.iter().all(|name| name.ends_with(".yaml")));

    if !go_copy.is_dir() {
        return; // Go tree already deleted: crate-local assets are authoritative.
    }
    let mut go_names: Vec<String> = fs::read_dir(&go_copy)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    go_names.sort();
    assert_eq!(names, go_names, "template file sets diverged");
    for name in &names {
        assert_eq!(
            fs::read(assets.join(name)).unwrap(),
            fs::read(go_copy.join(name)).unwrap(),
            "{name} drifted from the Go copy"
        );
    }
}
