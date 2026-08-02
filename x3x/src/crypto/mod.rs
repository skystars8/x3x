mod aead;
mod format;
mod legacy;

use crate::io_util::{IO_BUFFER_SIZE, NewOutput, local_path, open_regular_file};
use crate::{Algorithm, Mode};
use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::io::{BufReader, Read};
use std::path::Path;
use zeroize::Zeroizing;

/// Plaintext bytes processed per independently authenticated AEAD record.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Encrypt or decrypt two bare filenames within one directory.
///
/// # Errors
///
/// Returns an error for invalid filenames, missing or malformed inputs or keys,
/// authentication failure, I/O failure, or an existing output.
pub fn process_file_in(
    directory: &Path,
    algorithm: Algorithm,
    mode: Mode,
    input_name: &OsStr,
    output_name: &OsStr,
) -> Result<()> {
    let input_path = local_path(directory, input_name)?;
    let output_path = local_path(directory, output_name)?;
    let key_path = directory.join(algorithm.key_filename());

    if input_name == OsStr::new(algorithm.key_filename()) {
        bail!("refusing to process the active key file as input");
    }
    if output_name == OsStr::new(algorithm.key_filename()) {
        bail!("refusing to use the active key filename as output");
    }

    let key = read_key(&key_path, algorithm.key_len())?;
    match mode {
        Mode::Encrypt => encrypt_file(&input_path, &output_path, algorithm, &key),
        Mode::Decrypt => decrypt_file(&input_path, &output_path, algorithm, &key),
    }
}

fn read_key(path: &Path, expected_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file =
        open_regular_file(path).with_context(|| format!("required key is '{}'", path.display()))?;
    let actual_len = file
        .metadata()
        .with_context(|| format!("cannot inspect key '{}'", path.display()))?
        .len();
    if actual_len != expected_len as u64 {
        bail!(
            "key '{}' must contain exactly {expected_len} bytes, but contains {actual_len}",
            path.display()
        );
    }

    let mut reader = BufReader::new(file);
    let mut key = Zeroizing::new(vec![0_u8; expected_len]);
    reader
        .read_exact(&mut key)
        .with_context(|| format!("cannot read key '{}'", path.display()))?;
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        bail!("key '{}' changed while it was being read", path.display());
    }
    Ok(key)
}

fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    algorithm: Algorithm,
    key: &[u8],
) -> Result<()> {
    let input = open_regular_file(input_path)?;
    let plaintext_len = input
        .metadata()
        .with_context(|| format!("cannot inspect input '{}'", input_path.display()))?
        .len();

    let mut nonce_seed = [0_u8; 32];
    getrandom::fill(&mut nonce_seed)
        .map_err(|error| anyhow::anyhow!("operating-system random generator failed: {error}"))?;
    let header = format::Header::new(algorithm, plaintext_len, nonce_seed, CHUNK_SIZE);

    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let mut output = NewOutput::create(output_path)?;
    output
        .writer()
        .write_all(header.bytes())
        .context("cannot write encrypted file header")?;

    if algorithm.is_aead() {
        aead::encrypt(&mut reader, output.writer(), algorithm, key, &header)?;
    } else {
        legacy::encrypt(&mut reader, output.writer(), algorithm, key, &header)?;
    }

    ensure_eof(
        &mut reader,
        "input file changed while it was being encrypted",
    )?;
    output.finish()
}

fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    algorithm: Algorithm,
    key: &[u8],
) -> Result<()> {
    let input = open_regular_file(input_path)?;
    let encrypted_len = input
        .metadata()
        .with_context(|| format!("cannot inspect input '{}'", input_path.display()))?
        .len();
    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);

    let mut header_bytes = [0_u8; format::HEADER_LEN];
    reader
        .read_exact(&mut header_bytes)
        .context("encrypted file is too short to contain a complete header")?;
    let header = format::Header::parse(header_bytes, algorithm, CHUNK_SIZE)?;
    verify_encrypted_length(algorithm, &header, encrypted_len)?;

    let mut output = NewOutput::create(output_path)?;
    if algorithm.is_aead() {
        aead::decrypt(&mut reader, output.writer(), algorithm, key, &header)?;
    } else {
        legacy::decrypt(&mut reader, output.writer(), algorithm, key, &header)?;
    }
    ensure_eof(
        &mut reader,
        "encrypted file contains unexpected trailing data",
    )?;
    output.finish()
}

fn verify_encrypted_length(
    algorithm: Algorithm,
    header: &format::Header,
    encrypted_len: u64,
) -> Result<()> {
    let overhead = if algorithm.is_aead() {
        format::chunk_count(header.plaintext_len, CHUNK_SIZE)
            .checked_mul(algorithm.tag_len() as u64)
            .context("encrypted file length overflows")?
    } else {
        algorithm.tag_len() as u64
    };
    let expected = (format::HEADER_LEN as u64)
        .checked_add(header.plaintext_len)
        .and_then(|length| length.checked_add(overhead))
        .context("encrypted file length overflows")?;
    if encrypted_len != expected {
        bail!(
            "encrypted file has invalid length: expected {expected} bytes from its header, found {encrypted_len}"
        );
    }
    Ok(())
}

fn ensure_eof(reader: &mut impl Read, message: &str) -> Result<()> {
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        bail!("{message}");
    }
    Ok(())
}

use std::io::Write;
