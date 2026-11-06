//! `generate_template` with a custom `$HOME/.config/symvault/templates/*.tmpl`.
//!
//! Own test binary with a single test: it must set `HOME` (Go expands
//! `$HOME` at call time) without racing other tests. Expected bytes were
//! produced by the Go oracle (`symvault template generate --dry-run`, which
//! calls the same `Engine.Render` as the MCP tool).

use serde_json::Value;
use std::{fs, sync::Arc};
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    read_only_tool_names, run_stream,
};

#[derive(Clone)]
struct EmptyStore;

impl ReadOnlyStore for EmptyStore {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String> {
        Ok(Vec::new())
    }

    fn get(&self, _path: &str) -> Result<Option<ReadOnlyEntry>, String> {
        Ok(None)
    }
}

fn call(arguments: &str) -> Value {
    let mut tools = read_only_tool_names();
    tools.push("generate_template".into());
    let runtime = Arc::new(ReadOnlyRuntime::new(
        EmptyStore,
        ReadOnlyRuntimeConfig {
            server_name: "symvault".into(),
            server_version: "fixture".into(),
            transport: "stdio".into(),
            agent_name: "fixture".into(),
            approval_mode: "none".into(),
            allowed_paths: vec!["*".into()],
            available_tools: tools,
            vault_dir: "<fixture-vault>".into(),
            vault_unlocked: true,
            ..ReadOnlyRuntimeConfig::default()
        },
    ));
    let mut handler = ProtocolHandler::with_tool_call_runtime("symvault", "fixture", runtime);
    let call_line = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"generate_template","arguments":{arguments}}}}}"#
    );
    let input = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1"},"capabilities":{}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        call_line.as_str(),
    ]
    .iter()
    .map(|line| format!("{line}\n"))
    .collect::<String>();
    let lines = run_stream(&input, &mut handler).expect("stream");
    serde_json::from_str(lines.last().expect("response")).expect("JSON")
}

/// The text between the `<!-- DATA_x -->` boundaries of a wrapped payload.
fn payload(response: &Value) -> String {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text in {response}"));
    // The final MCP pass neutralizes `-->` into `-- >`.
    let start = text
        .find(" -->")
        .map(|i| i + 4)
        .or_else(|| text.find(" -- >").map(|i| i + 5))
        .expect("opening boundary");
    let end = text.rfind("<!-- /DATA_").expect("closing boundary");
    text[start..end].to_owned()
}

#[test]
fn custom_templates_render_through_the_go_interpreter() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".config/symvault/templates");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("mine.tmpl"),
        "# {{.Name | upper}}\n{{range $k, $v := .Refs}}{{$k}}={{index $.Values $k | printf \"%q\"}} <- {{$v}}\n{{end}}{{tojson .}}\n",
    )
    .unwrap();
    fs::write(dir.join("broken.tmpl"), "a\n{{.Nope}}\n").unwrap();
    fs::write(dir.join("unclosed.tmpl"), "x {{if .Name").unwrap();
    // SAFETY: this binary contains exactly one test, so nothing else reads
    // or writes the environment concurrently.
    unsafe { std::env::set_var("HOME", home.path()) };

    let ok = call(
        r#"{"template_type":"mine","name":"my app","dry_run":true,"secret_refs":{"Z":"work/item2.password","A":"op://work/item2/password"}}"#,
    );
    assert_eq!(
        payload(&ok),
        "# MY APP\nA=\"***\" <- op://work/item2/password\nZ=\"***\" <- work/item2.password\n{\"Name\":\"my app\",\"Refs\":{\"A\":\"op://work/item2/password\",\"Z\":\"work/item2.password\"},\"Values\":{\"A\":\"***\",\"Z\":\"***\"}}\n"
    );

    let exec = call(r#"{"template_type":"broken","dry_run":true}"#);
    assert_eq!(exec["result"]["isError"], true);
    assert_eq!(
        exec["result"]["content"][0]["text"],
        "render template: execute template \"broken\": template: broken:2:2: executing \"broken\" at <.Nope>: can't evaluate field Nope in type template.RenderData"
    );

    let parse = call(r#"{"template_type":"unclosed","dry_run":true}"#);
    assert_eq!(parse["result"]["isError"], true);
    assert_eq!(
        parse["result"]["content"][0]["text"],
        "render template: parse template \"unclosed\": template: unclosed:1: unclosed action"
    );
}
