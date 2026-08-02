use anyhow::{Result, bail};
use std::fmt;

/// Encryption algorithms supported by the standalone cipher binaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    Aes256GcmSiv = 1,
    XChaCha20Poly1305 = 2,
    Serpent256 = 3,
    Threefish1024 = 4,
    AsconAead128 = 5,
    Rabbit = 6,
    Aegis256 = 7,
    Aegis128L = 8,
}

impl Algorithm {
    pub(crate) const fn id(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Aes256GcmSiv),
            2 => Ok(Self::XChaCha20Poly1305),
            3 => Ok(Self::Serpent256),
            4 => Ok(Self::Threefish1024),
            5 => Ok(Self::AsconAead128),
            6 => Ok(Self::Rabbit),
            7 => Ok(Self::Aegis256),
            8 => Ok(Self::Aegis128L),
            _ => bail!("unknown algorithm identifier {id}"),
        }
    }

    /// Fixed key filename expected in the working directory.
    #[must_use]
    pub const fn key_filename(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aes.key",
            Self::XChaCha20Poly1305 => "cha.key",
            Self::Serpent256 => "ser.key",
            Self::Threefish1024 => "thf.key",
            Self::AsconAead128 => "asc.key",
            Self::Rabbit => "rab.key",
            Self::Aegis256 => "aegis256.key",
            Self::Aegis128L => "aegis128l.key",
        }
    }

    /// Exact raw key length accepted by the algorithm.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv | Self::XChaCha20Poly1305 | Self::Serpent256 | Self::Aegis256 => 32,
            Self::Threefish1024 => 128,
            Self::AsconAead128 | Self::Rabbit | Self::Aegis128L => 16,
        }
    }

    pub(crate) const fn is_aead(self) -> bool {
        matches!(
            self,
            Self::Aes256GcmSiv
                | Self::XChaCha20Poly1305
                | Self::AsconAead128
                | Self::Aegis256
                | Self::Aegis128L
        )
    }

    pub(crate) const fn tag_len(self) -> usize {
        if self.is_aead() { 16 } else { 64 }
    }

    pub(crate) const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv => 12,
            Self::XChaCha20Poly1305 => 24,
            Self::AsconAead128 | Self::Aegis128L => 16,
            Self::Aegis256 | Self::Serpent256 | Self::Threefish1024 | Self::Rabbit => 32,
        }
    }

    /// Command name of the standalone binary for this algorithm.
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aes",
            Self::XChaCha20Poly1305 => "cha",
            Self::Serpent256 => "ser",
            Self::Threefish1024 => "thf",
            Self::AsconAead128 => "asc",
            Self::Rabbit => "rabbit",
            Self::Aegis256 => "aegis256",
            Self::Aegis128L => "aegis128l",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Serpent256 => "Serpent-256-CTR + HMAC-SHA-512",
            Self::Threefish1024 => "Threefish-1024-CTR + HMAC-SHA-512",
            Self::AsconAead128 => "Ascon-AEAD128",
            Self::Rabbit => "Rabbit + HMAC-SHA-512",
            Self::Aegis256 => "AEGIS-256",
            Self::Aegis128L => "AEGIS-128L",
        };
        f.write_str(name)
    }
}

/// Operation selected by the required uppercase command argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl Mode {
    /// Parse the mandatory uppercase operation.
    ///
    /// # Errors
    /// Returns an error unless value is exactly E or D.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "E" => Ok(Self::Encrypt),
            "D" => Ok(Self::Decrypt),
            _ => bail!("operation must be exactly E or D (uppercase)"),
        }
    }
}
