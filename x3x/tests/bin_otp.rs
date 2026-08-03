#[path = "common/process.rs"]
mod process;

use process::{assert_failure_contains, assert_success, run, run_in, stdout};
use std::fs;

const BINARY: &str = env!("CARGO_BIN_EXE_otp");

#[test]
fn reports_usage_for_wrong_argument_counts() {
    for arguments in [
        Vec::<&str>::new(),
        vec!["input"],
        vec!["input", "key", "extra"],
    ] {
        assert_failure_contains(
            &run(BINARY, &arguments),
            "usage: otp [file to process] [key file]",
        );
    }
}

#[test]
fn xors_every_input_byte_with_the_key() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    let input = b"the plaintext";
    let key = b"a secret mask";
    fs::write(directory.path().join("input"), input).expect("write OTP input");
    fs::write(directory.path().join("key"), key).expect("write OTP key");
    assert_success(&run_in(BINARY, directory.path(), &["input", "key"]));
    let expected: Vec<u8> = input
        .iter()
        .zip(key)
        .map(|(byte, mask)| byte ^ mask)
        .collect();
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read transformed input"),
        expected
    );
}

#[test]
fn running_twice_restores_the_original() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    let input = b"round trip contents";
    let key = b"long enough key data!";
    fs::write(directory.path().join("input"), input).expect("write OTP input");
    fs::write(directory.path().join("key"), key).expect("write OTP key");
    assert_success(&run_in(BINARY, directory.path(), &["input", "key"]));
    assert_success(&run_in(BINARY, directory.path(), &["input", "key"]));
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read restored input"),
        input
    );
}

#[test]
fn streams_across_the_internal_buffer_boundary() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    let input: Vec<u8> = (0..x3x::CHUNK_SIZE + 97)
        .map(|index| u8::try_from(index % 251).expect("test byte fits in u8"))
        .collect();
    let key: Vec<u8> = (0..input.len())
        .map(|index| {
            u8::try_from(index % 256)
                .expect("test byte fits in u8")
                .wrapping_mul(73)
                .wrapping_add(19)
        })
        .collect();
    fs::write(directory.path().join("input"), &input).expect("write large OTP input");
    fs::write(directory.path().join("key"), &key).expect("write large OTP key");
    assert_success(&run_in(BINARY, directory.path(), &["input", "key"]));
    let actual = fs::read(directory.path().join("input")).expect("read transformed input");
    assert!(
        actual
            .iter()
            .zip(&input)
            .zip(&key)
            .all(|((value, original), mask)| *value == (*original ^ *mask))
    );
}

#[test]
fn accepts_a_key_longer_than_the_input() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    fs::write(directory.path().join("input"), [1_u8, 2, 3]).expect("write OTP input");
    fs::write(directory.path().join("key"), [4_u8, 5, 6, 7, 8]).expect("write OTP key");
    assert_success(&run_in(BINARY, directory.path(), &["input", "key"]));
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read transformed input"),
        [5_u8, 7, 5]
    );
}

#[test]
#[allow(clippy::permissions_set_readonly_false)]
fn preserves_readonly_permissions() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    let input_path = directory.path().join("input");
    fs::write(&input_path, [1_u8, 2, 3]).expect("write OTP input");
    fs::write(directory.path().join("key"), [4_u8, 5, 6]).expect("write OTP key");

    let mut permissions = fs::metadata(&input_path)
        .expect("inspect OTP input")
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&input_path, permissions).expect("make OTP input read-only");

    let output = run_in(BINARY, directory.path(), &["input", "key"]);
    let readonly = fs::metadata(&input_path)
        .expect("inspect transformed OTP input")
        .permissions()
        .readonly();

    #[cfg(windows)]
    {
        let mut cleanup_permissions = fs::metadata(&input_path)
            .expect("inspect transformed OTP input for cleanup")
            .permissions();
        cleanup_permissions.set_readonly(false);
        fs::set_permissions(&input_path, cleanup_permissions)
            .expect("make transformed OTP input removable");
    }

    assert_success(&output);
    assert!(readonly, "OTP replacement lost the read-only permission");
}

#[test]
fn accepts_separate_empty_input_and_key_files() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    fs::write(directory.path().join("input"), []).expect("write empty OTP input");
    fs::write(directory.path().join("key"), []).expect("write empty OTP key");
    assert_success(&run_in(BINARY, directory.path(), &["input", "key"]));
    assert!(
        fs::read(directory.path().join("input"))
            .expect("read empty OTP input")
            .is_empty()
    );
}

#[test]
fn rejects_a_short_key_without_changing_input() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    fs::write(directory.path().join("input"), b"preserve this").expect("write OTP input");
    fs::write(directory.path().join("key"), b"short").expect("write OTP key");
    let output = run_in(BINARY, directory.path(), &["input", "key"]);
    assert_failure_contains(&output, "OTP key is too short");
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read preserved input"),
        b"preserve this"
    );
}

#[test]
fn rejects_using_the_input_as_its_own_key() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    fs::write(directory.path().join("input"), b"preserve this").expect("write OTP input");
    let output = run_in(BINARY, directory.path(), &["input", "input"]);
    assert_failure_contains(
        &output,
        "input file and OTP key file must be different files",
    );
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read preserved input"),
        b"preserve this"
    );
}

#[test]
fn rejects_missing_input() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    fs::write(directory.path().join("key"), b"key").expect("write OTP key");
    assert_failure_contains(
        &run_in(BINARY, directory.path(), &["missing", "key"]),
        "cannot resolve input",
    );
}

#[test]
fn rejects_missing_key_without_changing_input() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    fs::write(directory.path().join("input"), b"preserve this").expect("write OTP input");
    let output = run_in(BINARY, directory.path(), &["input", "missing"]);
    assert_failure_contains(&output, "cannot resolve key");
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read preserved input"),
        b"preserve this"
    );
}

#[test]
fn rejects_nonlocal_and_nonportable_names() {
    for (input, key) in [
        ("folder/input", "key"),
        ("folder\\input", "key"),
        ("NUL", "key"),
        ("input", "folder/key"),
        ("input", "bad:key"),
        ("input", "COM1"),
    ] {
        let directory = tempfile::tempdir().expect("create OTP test directory");
        fs::write(directory.path().join("input"), b"preserve").expect("write OTP input");
        fs::write(directory.path().join("key"), b"long enough").expect("write OTP key");
        let output = run_in(BINARY, directory.path(), &[input, key]);
        assert_failure_contains(&output, "error:");
        assert_eq!(
            fs::read(directory.path().join("input")).expect("read preserved input"),
            b"preserve"
        );
    }
}

#[test]
fn reports_the_processed_filename() {
    let directory = tempfile::tempdir().expect("create OTP test directory");
    fs::write(directory.path().join("message.bin"), b"message").expect("write OTP input");
    fs::write(directory.path().join("key.bin"), b"keydata").expect("write OTP key");
    let output = run_in(BINARY, directory.path(), &["message.bin", "key.bin"]);
    assert_success(&output);
    assert!(stdout(&output).contains("OTP processing complete: 'message.bin'"));
}
