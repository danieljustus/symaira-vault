use std::{fs, path::Path, process::Command};

use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");

#[test]
fn generate_manpages_writes_command_pages_and_reports_absolute_directory() {
    let temp = TempDir::new().expect("temp directory");
    let unused = temp.path().join("unused");
    fs::create_dir(&unused).expect("create path component");
    let output_dir = temp.path().join("man");
    let requested_dir = unused.join("..").join("man");
    let output = Command::new(BINARY)
        .args(["--quiet", "generate", "manpages"])
        .arg(&requested_dir)
        .output()
        .expect("run symvault generate manpages");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("Generated manpages in {}\n", output_dir.display()),
        "the Go command reports the absolute output path even with --quiet"
    );

    let pages: Vec<_> = fs::read_dir(&output_dir)
        .expect("read generated pages")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "1"))
        .collect();
    assert!(
        pages.len() > 1,
        "expected root and nested man pages, got {pages:?}"
    );
    let root_page = pages
        .iter()
        .find(|path| path.file_name().is_some_and(|name| name == "symvault.1"))
        .expect("root man page");
    let root_contents = fs::read_to_string(root_page).expect("read root man page");
    assert!(root_contents.contains(".SH NAME"), "missing NAME section");
    assert!(root_contents.contains("symvault"), "missing command name");
}

#[test]
fn generate_manpages_reports_directory_creation_errors() {
    let temp = TempDir::new().expect("temp directory");
    let obstruction = temp.path().join("file");
    fs::write(&obstruction, "not a directory").expect("create path obstruction");
    let output_dir = obstruction.join("man");
    let output = Command::new(BINARY)
        .args(["generate", "manpages"])
        .arg(&output_dir)
        .output()
        .expect("run symvault generate manpages");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("Error: create manpage directory:"),
        "unexpected error: {stderr}"
    );
    assert!(Path::new(&obstruction).is_file());
}
