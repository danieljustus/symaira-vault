use serde_json::{Value, json};
use std::fs;
use symvault_mcp::store_adapter::load_api_template_definition;

#[test]
fn named_templates_match_actual_go_loader_and_custom_precedence() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/api-templates.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let root = tempfile::tempdir().unwrap();
        let name = case["template"].as_str().unwrap();
        if case["directory"] == true {
            fs::create_dir(root.path().join("templates")).unwrap();
        }
        if let Some(yaml) = case["override"].as_str() {
            fs::write(
                root.path().join("templates").join(format!("{name}.yaml")),
                yaml,
            )
            .unwrap();
        }
        let loaded = load_api_template_definition(root.path(), name);
        if case.get("error").is_some() {
            assert!(loaded.is_err(), "{} must reject", case["name"]);
            // YAML diagnostic wording differs by parser. Unknown named assets
            // have an exact Go error; other rejected inputs compare outcome.
            if case["name"] == "unknown" {
                assert_eq!(loaded.unwrap_err(), case["error"].as_str().unwrap());
            }
            continue;
        }
        let loaded = loaded.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
        let mut actual = json!({
            "name": name, "base_url": loaded.base_url, "auth_type": loaded.auth_type,
            "entry_ref": loaded.entry_ref, "allowed_endpoints": loaded.allowed_endpoints,
            "allowed_methods": loaded.allowed_methods,
        });
        if !loaded.default_headers.is_empty() {
            actual["default_headers"] = json!(loaded.default_headers);
        }
        if !loaded.substitutions.is_empty() {
            actual["substitutions"] = Value::Array(
                loaded
                    .substitutions
                    .iter()
                    .map(|sub| {
                        let mut value = json!({"placeholder": sub.placeholder, "field": sub.field});
                        if !sub.surfaces.is_empty() {
                            value["in"] = json!(sub.surfaces);
                        }
                        value
                    })
                    .collect(),
            );
        }
        if loaded.allow_private {
            actual["allow_private"] = true.into();
        }
        assert_eq!(actual, case["definition"], "{}", case["name"]);
    }
}

#[cfg(unix)]
#[test]
fn invalid_custom_paths_never_fall_back_to_builtin_credentials() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let templates = root.path().join("templates");
    fs::create_dir(&templates).unwrap();
    symlink(root.path().join("missing"), templates.join("github.yaml")).unwrap();
    assert!(load_api_template_definition(root.path(), "github").is_err());

    let root = tempfile::tempdir().unwrap();
    symlink(root.path().join("missing"), root.path().join("templates")).unwrap();
    assert!(load_api_template_definition(root.path(), "github").is_err());
}
