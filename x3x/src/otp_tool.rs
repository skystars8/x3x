use crate::io_util::{IO_BUFFER_SIZE, local_path, open_regular_file};
use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// XOR a file with the beginning of a key file and atomically replace the
/// explicitly named input only after the full transformed file is durable.
///
/// # Errors
///
/// Returns an error for invalid filenames, identical input and key, a key
/// shorter than the input, non-regular files, or any I/O or replacement
/// failure.
pub fn xor_file_in_place(directory: &Path, input_name: &OsStr, key_name: &OsStr) -> Result<()> {
    let input_path = local_path(directory, input_name)?;
    let key_path = local_path(directory, key_name)?;

    let canonical_input = std::fs::canonicalize(&input_path)
        .with_context(|| format!("cannot resolve input '{}'", input_path.display()))?;
    let canonical_key = std::fs::canonicalize(&key_path)
        .with_context(|| format!("cannot resolve key '{}'", key_path.display()))?;
    if canonical_input == canonical_key {
        bail!("input file and OTP key file must be different files");
    }

    let input = open_regular_file(&input_path)?;
    let input_metadata = input
        .metadata()
        .with_context(|| format!("cannot inspect input '{}'", input_path.display()))?;
    let input_len = input_metadata.len();

    let key = open_regular_file(&key_path)?;
    let key_len = key
        .metadata()
        .with_context(|| format!("cannot inspect key '{}'", key_path.display()))?
        .len();
    if key_len < input_len {
        bail!("OTP key is too short: input is {input_len} bytes but key is only {key_len} bytes");
    }

    let mut temporary = tempfile::NamedTempFile::new_in(directory).with_context(|| {
        format!(
            "cannot create temporary output in '{}'",
            directory.display()
        )
    })?;
    {
        let mut input_reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
        let mut key_reader = BufReader::with_capacity(IO_BUFFER_SIZE, key);
        let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, temporary.as_file_mut());
        let mut input_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
        let mut key_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
        let mut remaining = input_len;

        while remaining != 0 {
            let length = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64))
                .context("buffer length does not fit this platform")?;
            input_reader
                .read_exact(&mut input_buffer[..length])
                .context("input changed while OTP was running")?;
            key_reader
                .read_exact(&mut key_buffer[..length])
                .context("key changed while OTP was running")?;
            for (byte, key_byte) in input_buffer[..length].iter_mut().zip(&key_buffer[..length]) {
                *byte ^= *key_byte;
            }
            writer
                .write_all(&input_buffer[..length])
                .context("cannot write OTP temporary output")?;
            input_buffer[..length].zeroize();
            key_buffer[..length].zeroize();
            remaining -= length as u64;
        }

        let mut extra = [0_u8; 1];
        if input_reader.read(&mut extra)? != 0 {
            bail!("input grew while OTP was running");
        }
        writer
            .flush()
            .context("cannot flush OTP temporary output")?;
    }

    temporary
        .as_file()
        .sync_all()
        .context("cannot sync OTP temporary output")?;
    temporary
        .as_file()
        .set_permissions(input_metadata.permissions())
        .context("cannot preserve input file permissions")?;
    temporary
        .persist(&input_path)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot atomically replace '{}'", input_path.display()))?;

    #[cfg(unix)]
    {
        std::fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .with_context(|| format!("cannot sync directory '{}'", directory.display()))?;
    }
    Ok(())
}
