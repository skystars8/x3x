use crate::Algorithm;
use anyhow::{Result, bail};

pub(super) const HEADER_LEN: usize = 64;
const MAGIC: &[u8; 8] = b"X3XCRYPT";
const FORMAT_VERSION: u8 = 1;

#[derive(Clone)]
pub(super) struct Header {
    bytes: [u8; HEADER_LEN],
    pub(super) plaintext_len: u64,
    pub(super) nonce_seed: [u8; 32],
}

impl Header {
    pub(super) fn new(
        algorithm: Algorithm,
        plaintext_len: u64,
        nonce_seed: [u8; 32],
        chunk_size: usize,
    ) -> Self {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = FORMAT_VERSION;
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
        }
    }

    pub(super) fn parse(
        bytes: [u8; HEADER_LEN],
        expected_algorithm: Algorithm,
        expected_chunk_size: usize,
    ) -> Result<Self> {
        if &bytes[..8] != MAGIC {
            bail!("input is not an x3x encrypted file");
        }
        if bytes[8] != FORMAT_VERSION {
            bail!("unsupported x3x format version {}", bytes[8]);
        }
        let actual_algorithm = Algorithm::from_id(bytes[9])?;
        if actual_algorithm != expected_algorithm {
            bail!(
                "file uses {actual_algorithm}, not {expected_algorithm}; use the matching binary"
            );
        }
        if usize::from(bytes[10]) != expected_algorithm.tag_len()
            || usize::from(bytes[11]) != expected_algorithm.nonce_len()
        {
            bail!("invalid algorithm parameters in encrypted file header");
        }
        let chunk_size = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice"));
        if usize::try_from(chunk_size).ok() != Some(expected_chunk_size) {
            bail!("unsupported encrypted file chunk size {chunk_size}");
        }
        if bytes[56..].iter().any(|byte| *byte != 0) {
            bail!("encrypted file header has nonzero reserved bytes");
        }

        let plaintext_len = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed slice"));
        let mut nonce_seed = [0_u8; 32];
        nonce_seed.copy_from_slice(&bytes[24..56]);
        Ok(Self {
            bytes,
            plaintext_len,
            nonce_seed,
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
