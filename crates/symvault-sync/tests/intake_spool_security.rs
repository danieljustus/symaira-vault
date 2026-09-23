use std::fs;

use symvault_sync::intake::Spool;
use tempfile::tempdir;

#[test]
fn staged_copies_are_private_unique_and_removed_with_spool() {
    let home = tempdir().unwrap();
    let parent = home.path().join("spool-parent");
    let source = home.path().join("sample.env");
    let first = b"sample-one\n";
    let second = b"sample-two\n";
    fs::write(&source, first).unwrap();

    let spool = Spool::new(&parent).unwrap();
    let private_root = spool.root().to_path_buf();
    assert_ne!(private_root, parent);
    assert!(private_root.starts_with(&parent));

    assert_eq!(spool.stage(&source, 1024).unwrap().0, first);
    fs::write(&source, second).unwrap();
    assert_eq!(spool.stage(&source, 1024).unwrap().0, second);
    let mut staged = fs::read_dir(&private_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    staged.sort();
    assert_eq!(
        staged.len(),
        2,
        "neither staged copy may overwrite the other"
    );
    let mut contents = staged
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    contents.sort();
    assert_eq!(contents, vec![first.to_vec(), second.to_vec()]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&private_root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for path in &staged {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    assert!(
        spool.stage(&source, 3).is_err(),
        "limit must reject oversized sources"
    );
    assert_eq!(fs::read(&source).unwrap(), second);
    drop(spool);
    assert!(
        !private_root.exists(),
        "private staging must be cleaned on drop"
    );
    assert_eq!(fs::read(&source).unwrap(), second);
}

#[cfg(unix)]
#[test]
fn spool_parent_and_source_symlinks_are_rejected() {
    let home = tempdir().unwrap();
    let parent = home.path().join("parent");
    fs::create_dir(&parent).unwrap();
    let alias = home.path().join("alias");
    std::os::unix::fs::symlink(&parent, &alias).unwrap();
    assert!(Spool::new(&alias).is_err());

    let spool = Spool::new(&parent).unwrap();
    let source = home.path().join("source.txt");
    fs::write(&source, b"sample").unwrap();
    let link = home.path().join("link.txt");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert!(spool.stage(&link, 1024).is_err());
    assert_eq!(fs::read_dir(spool.root()).unwrap().count(), 0);
}
