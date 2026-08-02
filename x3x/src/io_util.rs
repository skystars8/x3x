use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Component, Path, PathBuf};

pub(crate) const IO_BUFFER_SIZE: usize = 1024 * 1024;

/// Accept only a single filename component. This deliberately rejects absolute
/// paths, directory traversal, and even dot prefixes for identical behavior on
/// all supported operating systems.
pub(crate) fn validate_filename(name: &OsStr) -> Result<()> {
    let text = name
        .to_str()
        .context("filenames must be valid Unicode for cross-platform use")?;
    if text
        .chars()
        .any(|character| matches!(character, '/' | '\\' | ':'))
        || text.ends_with(['.', ' '])
    {
        bail!("filename contains characters that are not portable across operating systems");
    }

    let base = text
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let is_reserved_word = matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    );
    let is_reserved_numbered = base.len() == 4
        && matches!(&base[..3], "COM" | "LPT")
        && matches!(base.as_bytes()[3], b'1'..=b'9');
    if is_reserved_word || is_reserved_numbered {
        bail!("filename is a reserved device name on Windows");
    }

    let path = Path::new(name);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => bail!("files must be specified by filename only and must be in the working directory"),
    }
}

pub(crate) fn local_path(directory: &Path, name: &OsStr) -> Result<PathBuf> {
    validate_filename(name)?;
    Ok(directory.join(name))
}

pub(crate) fn open_regular_file(path: &Path) -> Result<File> {
    let file =
        File::open(path).with_context(|| format!("cannot open input file '{}'", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect input file '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("'{}' is not a regular file", path.display());
    }
    Ok(file)
}

pub(crate) fn ensure_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to overwrite existing file '{}'", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("cannot inspect output path '{}'", path.display()))
        }
    }
}

/// A private temporary output installed only when finish completes.
pub(crate) struct NewOutput {
    path: PathBuf,
    writer: Option<BufWriter<tempfile::NamedTempFile>>,
}

impl NewOutput {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        ensure_absent(path)?;
        let parent = path
            .parent()
            .context("output path does not have a parent directory")?;
        let temporary = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("cannot create temporary output in '{}'", parent.display()))?;
        Ok(Self {
            path: path.to_owned(),
            writer: Some(BufWriter::with_capacity(IO_BUFFER_SIZE, temporary)),
        })
    }

    pub(crate) fn writer(&mut self) -> &mut BufWriter<tempfile::NamedTempFile> {
        self.writer.as_mut().expect("output writer is present")
    }

    pub(crate) fn finish(mut self) -> Result<()> {
        let mut writer = self.writer.take().expect("output writer is present");
        writer
            .flush()
            .with_context(|| format!("cannot flush output '{}'", self.path.display()))?;
        writer
            .get_ref()
            .as_file()
            .sync_all()
            .with_context(|| format!("cannot sync output '{}'", self.path.display()))?;
        let temporary = writer
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)
            .context("cannot finalize buffered output")?;
        temporary
            .persist_noclobber(&self.path)
            .map_err(|error| error.error)
            .with_context(|| format!("refusing to overwrite output '{}'", self.path.display()))?;
        Ok(())
    }
}
