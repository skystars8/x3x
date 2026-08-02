use super::password::{KDF_ID_ARGON2ID, PasswordKdf};
use crate::Algorithm;
use anyhow::{Result, bail};

pub(super) const HEADER_LEN: usize = 64;
const MAGIC: &[u8; 8] = b"X3XCRYPT";
const KEY_FILE_FORMAT_VERSION: u8 = 1;
const PASSWORD_FORMAT_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Keying {
    KeyFile,
    Password(PasswordKdf),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExpectedKeying {
    KeyFile,
    Password,
}

#[derive(Clone)]
pub(super) struct Header {
    bytes: [u8; HEADER_LEN],
    pub(super) plaintext_len: u64,
    pub(super) nonce_seed: [u8; 32],
    pub(super) keying: Keying,
}

impl Header {
    pub(super) fn new(
        algorithm: Algorithm,
        plaintext_len: u64,
        nonce_seed: [u8; 32],
        chunk_size: usize,
        keying: Keying,
    ) -> Self {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = match keying {
            Keying::KeyFile => KEY_FILE_FORMAT_VERSION,
            Keying::Password(parameters) => {
                bytes[56..60].copy_from_slice(&parameters.memory_kib.to_le_bytes());
                bytes[60..62].copy_from_slice(&parameters.iterations.to_le_bytes());
                bytes[62] = parameters.lanes;
                bytes[63] = KDF_ID_ARGON2ID;
                PASSWORD_FORMAT_VERSION
            }
        };
        bytes[9] = algorithm.id();
        bytes[10] = u8::try_from(algorithm.tag_len()).expect("tag length fits in u8");
        bytes[11] = u8::try_from(algorithm.nonce_len()).expect("nonce length fits in u8");
        bytes[12..16].copy_from_slice(
            &u32::try_from(chunk_size)
                .expect("chunk size fits in u32")
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
        bytes[24..56].copy_from_slice(&nonce_seed);
        Self {
            bytes,
            plaintext_len,
            nonce_seed,
            keying,
        }
    }

    pub(super) fn parse(
        bytes: [u8; HEADER_LEN],
        expected_algorithm: Algorithm,
        expected_chunk_size: usize,
        expected_keying: ExpectedKeying,
    ) -> Result<Self> {
        if &bytes[..8] != MAGIC {
            bail!("input is not an x3x encrypted file");
        }
        let actual_algorithm = Algorithm::from_id(bytes[9])?;
        if actual_algorithm != expected_algorithm {
            bail!(
                "file uses {actual_algorithm}, not {expected_algorithm}; use the matching binary"
            );
        }
        let keying = match bytes[8] {
            KEY_FILE_FORMAT_VERSION => {
                if expected_keying == ExpectedKeying::Password {
                    bail!(
                        "file uses a key file; use the '{}' binary",
                        expected_algorithm.command()
                    );
                }
                if bytes[56..].iter().any(|byte| *byte != 0) {
                    bail!("encrypted file header has nonzero reserved bytes");
                }
                Keying::KeyFile
            }
            PASSWORD_FORMAT_VERSION => {
                if expected_keying == ExpectedKeying::KeyFile {
                    bail!(
                        "file is password-protected; use the '{}' binary",
                        expected_algorithm.password_command()
                    );
                }
                if bytes[63] != KDF_ID_ARGON2ID {
                    bail!("unsupported password KDF identifier {}", bytes[63]);
                }
                let memory_kib = u32::from_le_bytes(bytes[56..60].try_into().expect("fixed slice"));
                let iterations = u16::from_le_bytes(bytes[60..62].try_into().expect("fixed slice"));
                let parameters = PasswordKdf::from_header(memory_kib, iterations, bytes[62])?;
                Keying::Password(parameters)
            }
            version => bail!("unsupported x3x format version {version}"),
        };
        if usize::from(bytes[10]) != expected_algorithm.tag_len()
            || usize::from(bytes[11]) != expected_algorithm.nonce_len()
        {
            bail!("invalid algorithm parameters in encrypted file header");
        }
        let chunk_size = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice"));
        if usize::try_from(chunk_size).ok() != Some(expected_chunk_size) {
            bail!("unsupported encrypted file chunk size {chunk_size}");
        }
        let plaintext_len = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed slice"));
        let mut nonce_seed = [0_u8; 32];
        nonce_seed.copy_from_slice(&bytes[24..56]);
        Ok(Self {
            bytes,
            plaintext_len,
            nonce_seed,
            keying,
        })
    }

    pub(super) fn bytes(&self) -> &[u8; HEADER_LEN] {
        &self.bytes
    }
}

pub(super) fn chunk_count(plaintext_len: u64, chunk_size: usize) -> u64 {
    if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(chunk_size as u64)
    }
}

pub(super) fn chunk_plaintext_len(
    plaintext_len: u64,
    chunk_size: usize,
    chunk_index: u64,
) -> usize {
    if plaintext_len == 0 {
        return 0;
    }
    let offset = chunk_index
        .checked_mul(chunk_size as u64)
        .expect("valid chunk offset");
    usize::try_from((plaintext_len - offset).min(chunk_size as u64))
        .expect("chunk length fits in usize")
}

pub(super) fn chunk_aad(
    header: &Header,
    chunk_index: u64,
    plaintext_len: usize,
    is_final: bool,
) -> [u8; 80] {
    let mut aad = [0_u8; 80];
    aad[..HEADER_LEN].copy_from_slice(header.bytes());
    aad[64..72].copy_from_slice(&chunk_index.to_le_bytes());
    aad[72..76].copy_from_slice(
        &u32::try_from(plaintext_len)
            .expect("chunk length fits in u32")
            .to_le_bytes(),
    );
    aad[76] = u8::from(is_final);
    aad
}

pub(super) fn chunk_nonce(seed: &[u8; 32], nonce_len: usize, chunk_index: u64) -> Vec<u8> {
    let mut nonce = seed[..nonce_len].to_vec();
    let index = chunk_index.to_be_bytes();
    let tail = nonce_len - index.len();
    for (output, counter) in nonce[tail..].iter_mut().zip(index) {
        *output ^= counter;
    }
    nonce
}
