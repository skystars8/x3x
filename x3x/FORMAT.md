# x3x encrypted file format version 1

All multibyte integers are little-endian. The fixed header is 64 bytes:

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 0 | 8 | ASCII X3XCRYPT |
| 8 | 1 | format version, currently 1 |
| 9 | 1 | algorithm identifier |
| 10 | 1 | authentication tag length |
| 11 | 1 | nonce-seed length used by the algorithm |
| 12 | 4 | plaintext chunk size, currently 1,048,576 |
| 16 | 8 | exact plaintext length |
| 24 | 32 | fresh operating-system random nonce seed |
| 56 | 8 | reserved, required to be zero |

Algorithm identifiers are 1 AES-256-GCM-SIV, 2 XChaCha20-Poly1305, 3
Serpent-256, 4 Threefish-1024, 5 Ascon-AEAD128, 6 Rabbit, 7 AEGIS-256, and 8
AEGIS-128L.

## AEAD records

There is one record per 1 MiB plaintext chunk. An empty file still has one
zero-length record so its header receives an authentication tag. A record is
ciphertext of the same length as its plaintext followed by a 16-byte tag.

The per-record nonce begins as the algorithm-sized prefix of the 32-byte nonce
seed. The big-endian 64-bit record index is XORed into its last eight bytes.
This preserves all random nonce bits while making every record nonce distinct
within a file.

Associated data is 80 bytes: the 64-byte header, 64-bit record index, 32-bit
record plaintext length, one byte that is 1 only for the final record, and three
zero bytes. It binds record order, the declared file length, algorithm, nonce
seed, chunk boundaries, and final record.

Decryption calculates the only valid total encrypted length from the header and
refuses truncated or trailing data before producing the requested output.

## Serpent, Threefish, and Rabbit records

These formats contain the header, ciphertext with the same length as the
plaintext, and a final 64-byte HMAC-SHA-512 tag.

HKDF-SHA-512 uses the 32-byte nonce seed as salt and the raw key file as input
key material. Domain-separated labels produce independent encryption keys,
tweaks or IVs, and 64-byte MAC keys for each algorithm and file.

Serpent uses its 256-bit derived key as a counter-mode keystream generator over
128-bit big-endian counters. Threefish-1024 uses a derived 1024-bit key and
128-bit tweak as a counter-mode keystream generator; the big-endian 128-bit
counter occupies the last 16 bytes of each 128-byte counter block. Rabbit uses a
derived 128-bit key and 64-bit IV. HMAC covers the exact header followed by all
ciphertext and is verified in constant time before the temporary plaintext is
installed at its requested name.

Any incompatible future change requires a new format version.
