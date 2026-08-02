#![allow(dead_code)]

mod process;

use process::{assert_failure_contains, run};

#[derive(Clone, Copy)]
pub struct PasswordCipherApp {
    pub command: &'static str,
    pub binary: &'static str,
}

fn expected_usage(app: PasswordCipherApp) -> String {
    format!("usage: {} [E or D] [filename] [output-file]", app.command)
}

pub fn reports_usage_without_arguments(app: PasswordCipherApp) {
    assert_failure_contains(&run(app.binary, &[]), &expected_usage(app));
}

pub fn reports_usage_with_one_argument(app: PasswordCipherApp) {
    assert_failure_contains(&run(app.binary, &["E"]), &expected_usage(app));
}

pub fn reports_usage_with_two_arguments(app: PasswordCipherApp) {
    assert_failure_contains(&run(app.binary, &["E", "input"]), &expected_usage(app));
}

pub fn reports_usage_with_extra_arguments(app: PasswordCipherApp) {
    assert_failure_contains(
        &run(app.binary, &["E", "input", "output", "extra"]),
        &expected_usage(app),
    );
}

pub fn rejects_lowercase_operations(app: PasswordCipherApp) {
    for operation in ["e", "d"] {
        assert_failure_contains(
            &run(app.binary, &[operation, "input", "output"]),
            "operation must be exactly E or D (uppercase)",
        );
    }
}

pub fn rejects_operation_words(app: PasswordCipherApp) {
    for operation in ["encrypt", "decrypt", "ENCRYPT", "DECRYPT"] {
        assert_failure_contains(
            &run(app.binary, &[operation, "input", "output"]),
            "operation must be exactly E or D (uppercase)",
        );
    }
}

pub fn rejects_empty_or_combined_operations(app: PasswordCipherApp) {
    for operation in ["", "ED", "DE", "-"] {
        assert_failure_contains(
            &run(app.binary, &[operation, "input", "output"]),
            "operation must be exactly E or D (uppercase)",
        );
    }
}

pub fn validates_operation_before_touching_files(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    std::fs::write(directory.path().join("output"), b"preserve me").expect("write sentinel output");
    let output = process::run_in(
        app.binary,
        directory.path(),
        &["invalid", "missing", "output"],
    );
    assert_failure_contains(&output, "operation must be exactly E or D (uppercase)");
    assert_eq!(
        std::fs::read(directory.path().join("output")).expect("read sentinel output"),
        b"preserve me"
    );
}

macro_rules! define_password_cipher_tests {
    ($binary:expr, $command:literal) => {
        const APP: $crate::common::PasswordCipherApp = $crate::common::PasswordCipherApp {
            command: $command,
            binary: $binary,
        };

        #[test]
        fn reports_usage_without_arguments() {
            $crate::common::reports_usage_without_arguments(APP);
        }

        #[test]
        fn reports_usage_with_one_argument() {
            $crate::common::reports_usage_with_one_argument(APP);
        }

        #[test]
        fn reports_usage_with_two_arguments() {
            $crate::common::reports_usage_with_two_arguments(APP);
        }

        #[test]
        fn reports_usage_with_extra_arguments() {
            $crate::common::reports_usage_with_extra_arguments(APP);
        }

        #[test]
        fn rejects_lowercase_operations() {
            $crate::common::rejects_lowercase_operations(APP);
        }

        #[test]
        fn rejects_operation_words() {
            $crate::common::rejects_operation_words(APP);
        }

        #[test]
        fn rejects_empty_or_combined_operations() {
            $crate::common::rejects_empty_or_combined_operations(APP);
        }

        #[test]
        fn validates_operation_before_touching_files() {
            $crate::common::validates_operation_before_touching_files(APP);
        }
    };
}

pub(crate) use define_password_cipher_tests;
