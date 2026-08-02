#[path = "common/process.rs"]
mod process;

use process::{assert_failure_contains, assert_success, run, run_in, stdout};
use std::fs;

const BINARY: &str = env!("CARGO_BIN_EXE_key2txt");

#[test]
fn reports_usage_for_wrong_argument_counts() {
    for arguments in [Vec::<&str>::new(), vec!["input", "extra"]] {
        assert_failure_contains(&run(BINARY, &arguments), "usage: key2txt [binary key file]");
    }
}

#[test]
fn converts_a_binary_key_to_documented_decimal_text() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("source.key"), [23_u8, 255, 53, 9, 5])
        .expect("write binary key");
    let output = run_in(BINARY, directory.path(), &["source.key"]);
    assert_success(&output);
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read decimal text"),
        b"23,\n255,\n53,\n9,\n5\n"
    );
}

#[test]
fn converts_every_possible_byte_value() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    let input: Vec<u8> = (0_u8..=u8::MAX).collect();
    fs::write(directory.path().join("all.key"), input).expect("write all byte values");
    assert_success(&run_in(BINARY, directory.path(), &["all.key"]));

    let expected = (0_u16..=u16::from(u8::MAX))
        .map(|value| {
            if value == u16::from(u8::MAX) {
                format!("{value}\n")
            } else {
                format!("{value},\n")
            }
        })
        .collect::<String>();
    assert_eq!(
        fs::read_to_string(directory.path().join("key2txt.txt")).expect("read converted values"),
        expected
    );
}

#[test]
fn converts_an_empty_file_to_an_empty_file() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("empty.key"), []).expect("write empty key");
    assert_success(&run_in(BINARY, directory.path(), &["empty.key"]));
    assert!(
        fs::read(directory.path().join("key2txt.txt"))
            .expect("read converted empty key")
            .is_empty()
    );
}

#[test]
fn streams_across_the_internal_buffer_boundary() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    let input: Vec<u8> = (0..x3x::CHUNK_SIZE + 31)
        .map(|index| u8::try_from(index % 256).expect("test byte fits in u8"))
        .collect();
    fs::write(directory.path().join("large.key"), &input).expect("write large key");
    assert_success(&run_in(BINARY, directory.path(), &["large.key"]));
    let text =
        fs::read_to_string(directory.path().join("key2txt.txt")).expect("read large conversion");
    assert_eq!(text.lines().count(), input.len());
    assert!(text.starts_with("0,\n1,\n2,\n"));
    assert!(text.ends_with(&format!("{}\n", input[input.len() - 1])));
}

#[test]
fn reports_the_source_and_fixed_output_names() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("named.key"), [1_u8]).expect("write source key");
    let output = run_in(BINARY, directory.path(), &["named.key"]);
    assert_success(&output);
    assert!(stdout(&output).contains("converted binary key 'named.key' to key2txt.txt"));
}

#[test]
fn rejects_a_missing_input_without_output() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    let output = run_in(BINARY, directory.path(), &["missing.key"]);
    assert_failure_contains(&output, "cannot open input file");
    assert!(!directory.path().join("key2txt.txt").exists());
}

#[test]
fn rejects_nonlocal_and_nonportable_input_names() {
    for input in ["folder/key", "folder\\key", "bad:name", "NUL", "trailing."] {
        let directory = tempfile::tempdir().expect("create key2txt test directory");
        let output = run_in(BINARY, directory.path(), &[input]);
        assert_failure_contains(&output, "error:");
        assert!(!directory.path().join("key2txt.txt").exists());
    }
}

#[test]
fn refuses_to_overwrite_the_fixed_output() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("source.key"), [1_u8, 2, 3]).expect("write source key");
    fs::write(directory.path().join("key2txt.txt"), b"preserve me").expect("write existing output");
    let output = run_in(BINARY, directory.path(), &["source.key"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read preserved output"),
        b"preserve me"
    );
}
