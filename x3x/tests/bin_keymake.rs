#[path = "common/process.rs"]
mod process;

use process::{assert_failure_contains, run, run_in};
use std::fs;

const BINARY: &str = env!("CARGO_BIN_EXE_keymake");

#[test]
fn reports_usage_without_arguments() {
    assert_failure_contains(&run(BINARY, &[]), "usage: keymake [size in bytes]");
}

#[test]
fn reports_usage_with_extra_arguments() {
    assert_failure_contains(
        &run(BINARY, &["32", "extra"]),
        "usage: keymake [size in bytes]",
    );
}

#[test]
fn rejects_non_decimal_sizes_before_prompting() {
    for size in ["abc", "1.0", "++1", "-1", " 32", "32 ", "32bytes"] {
        assert_failure_contains(&run(BINARY, &[size]), "invalid byte count");
    }
}

#[test]
fn rejects_zero_before_prompting() {
    assert_failure_contains(
        &run(BINARY, &["0"]),
        "size must be an exact byte count from 1 through 20000000000",
    );
}

#[test]
fn rejects_too_large_sizes_before_prompting() {
    for size in ["20000000001", "18446744073709551615"] {
        assert_failure_contains(
            &run(BINARY, &[size]),
            "size must be an exact byte count from 1 through 20000000000",
        );
    }
}

#[test]
fn refuses_an_existing_output_before_prompting() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    fs::write(directory.path().join("keymake.key"), b"preserve me").expect("write existing key");
    let output = run_in(BINARY, directory.path(), &["32"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("keymake.key")).expect("read preserved key"),
        b"preserve me"
    );
}

#[test]
fn invalid_size_never_creates_an_output() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    let output = run_in(BINARY, directory.path(), &["not-a-size"]);
    assert_failure_contains(&output, "invalid byte count");
    assert!(!directory.path().join("keymake.key").exists());
}
