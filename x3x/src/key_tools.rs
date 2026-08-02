use crate::io_util::{IO_BUFFER_SIZE, NewOutput, ensure_absent};
use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_KEY_SIZE: u64 = 20_000_000_000;
const ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_LANES: u32 = 4;

fn validate_size(size: u64) -> Result<()> {
    if !(1..=MAX_KEY_SIZE).contains(&size) {
        bail!("size must be an exact byte count from 1 through {MAX_KEY_SIZE}");
    }
    Ok(())
}

/// Create keygen.key from operating-system random bytes.
///
/// # Errors
///
/// Returns an error for an out-of-range size, existing output, unavailable
/// operating-system randomness, or an I/O failure.
pub fn generate_random_key_in(directory: &Path, size: u64) -> Result<()> {
    validate_size(size)?;
    let output_path = directory.join("keygen.key");
    let mut output = NewOutput::create(&output_path)?;
    let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut remaining = size;

    while remaining != 0 {
        let length = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64))
            .context("buffer length does not fit this platform")?;
        getrandom::fill(&mut buffer[..length])
            .map_err(|error| anyhow!("operating-system random generator failed: {error}"))?;
        output
            .writer()
            .write_all(&buffer[..length])
            .with_context(|| format!("cannot write '{}'", output_path.display()))?;
        buffer[..length].zeroize();
        remaining -= length as u64;
    }
    output.finish()
}

/// Deterministically derive keymake.key from a password.
///
/// # Errors
///
/// Returns an error for an invalid size or password, existing output, key
/// derivation failure, or an I/O failure.
pub fn make_deterministic_key_in(directory: &Path, size: u64, password: &[u8]) -> Result<()> {
    validate_size(size)?;
    if password.is_empty() {
        bail!("password must not be empty");
    }

    let output_path = directory.join("keymake.key");
    ensure_absent(&output_path)?;

    let salt = deterministic_salt(size);
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, Some(64))
        .map_err(|error| anyhow!("invalid Argon2id parameters: {error}"))?;
    let argon2 = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
    let mut root_key = Zeroizing::new([0_u8; 64]);
    argon2
        .hash_password_into(password, &salt, &mut *root_key)
        .map_err(|error| anyhow!("Argon2id key derivation failed: {error}"))?;

    let mut xof = Shake256::default();
    Update::update(&mut xof, b"x3x/keymake/v1/shake256");
    Update::update(&mut xof, &size.to_le_bytes());
    Update::update(&mut xof, &*root_key);
    let mut reader = xof.finalize_xof();

    let mut output = NewOutput::create(&output_path)?;
    let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut remaining = size;
    while remaining != 0 {
        let length = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64))
            .context("buffer length does not fit this platform")?;
        XofReader::read(&mut reader, &mut buffer[..length]);
        output
            .writer()
            .write_all(&buffer[..length])
            .with_context(|| format!("cannot write '{}'", output_path.display()))?;
        buffer[..length].zeroize();
        remaining -= length as u64;
    }
    output.finish()
}

fn deterministic_salt(size: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    Digest::update(&mut digest, b"x3x/keymake/v1/argon2id-salt");
    Digest::update(&mut digest, size.to_le_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_is_deterministic_and_size_separated() {
        assert_eq!(deterministic_salt(32), deterministic_salt(32));
        assert_ne!(deterministic_salt(32), deterministic_salt(33));
    }

    #[test]
    fn validates_full_size_range() {
        assert!(validate_size(1).is_ok());
        assert!(validate_size(MAX_KEY_SIZE).is_ok());
        assert!(validate_size(0).is_err());
        assert!(validate_size(MAX_KEY_SIZE + 1).is_err());
    }
}
