# x3x

x3x is a Rust 2024 collection of small, separate file-encryption and key-tool
binaries. The workspace is pinned to Rust 1.97.1 and builds with the local Rust
toolchain.

This is new cryptographic application code and has not received an independent
security audit. Keep backups until it has been reviewed for your use case.

## Build

From this directory:

~~~text
cargo build --release --bins
~~~

The executables are placed in target/release. Each one can be copied and used
independently. The original cipher programs look for their fixed key file in
the current working directory; the password variants do not use key files.

## Cipher binaries

| Key binary | Password binary | Construction | Required key file | Exact key size |
| --- | --- | --- | --- | ---: |
| aes | aesp | AES-256-GCM-SIV | aes.key | 32 bytes |
| cha | chap | XChaCha20-Poly1305 | cha.key | 32 bytes |
| ser | serp | Serpent-256-CTR with HMAC-SHA-512 | ser.key | 32 bytes |
| thf | thfp | Threefish-1024-CTR with HMAC-SHA-512 | thf.key | 128 bytes |
| asc | ascp | Ascon-AEAD128 | asc.key | 16 bytes |
| rabbit | rabbitp | Rabbit with HMAC-SHA-512 | rab.key | 16 bytes |
| aegis256 | aegis256p | AEGIS-256 | aegis256.key | 32 bytes |
| aegis128l | aegis128lp | AEGIS-128L | aegis128l.key | 16 bytes |

The AEGIS crate is compiled with its pure-Rust backend. Serpent, Threefish, and
Rabbit are unauthenticated primitives, so x3x derives independent per-file
encryption and MAC keys with HKDF-SHA-512 and authenticates the header and all
ciphertext with HMAC-SHA-512.

Every cipher has the same interface:

~~~text
aes E filename output-file
aes D filename output-file
~~~

Replace aes with the desired binary name. The operation is exactly uppercase E
or D. Input, output, and key must be in the current working directory, and input
and output arguments must be portable Unicode filenames without path
components, ASCII control characters, Windows-invalid punctuation
(`: * ? " < > |`), trailing dots or spaces, or Windows reserved device names.
This keeps filename behavior consistent across Windows, Linux, and macOS.

Outputs are never overwritten. Data is written to a private temporary file in
the same directory, flushed and synced, and installed only at successful
completion with a no-clobber operation. Authentication failure, truncation,
trailing bytes, a wrong algorithm, or a wrong key does not create the requested
output.

Cipher files use a versioned x3x container and are not raw output from the
underlying primitive. Files are streamed in 1 MiB chunks. AEAD ciphers
authenticate each chunk independently with its position and file metadata;
legacy constructions authenticate the complete ciphertext. See FORMAT.md for
the exact format.

## Password cipher binaries

The password binaries have the same file interface and add p to the command:

~~~text
aesp E filename output-file
aesp D filename output-file
~~~

Encryption prompts for the password twice; decryption prompts once. Password
input is hidden and is held in zeroizing memory. These binaries neither read
nor create an external key file.

Every encryption generates a fresh 32-byte operating-system random salt. The
password and salt are processed with Argon2id v1.3 using 512 MiB of memory, four
passes, and four lanes to derive a 64-byte root key. HKDF-SHA-512 then derives a
separate, algorithm-specific internal key of the exact required size. This
allows Threefish to receive a full 128-byte internal key without stretching a
short cipher key by repetition.

Password files use container version 2 and record their bounded KDF parameters.
The salt, algorithm, parameters, plaintext length, and all ciphertext are
authenticated by the selected construction. Key-file binaries only accept
version 1; password binaries only accept version 2 and report which matching
command to use.

Argon2id makes password guessing expensive but cannot add entropy to a weak
password. Use a long, unique passphrase. Losing the password makes the data
unrecoverable.

## Random key generator

~~~text
keygen 32
~~~

keygen accepts an exact decimal byte count from 1 through 20,000,000,000 and
streams operating-system random bytes into keygen.key. It refuses to overwrite
an existing keygen.key. Rename the result to the fixed cipher key filename when
using it.

Useful sizes are 16 bytes for asc, rabbit, or aegis128l; 32 bytes for aes, cha,
ser, or aegis256; and 128 bytes for thf.

## Deterministic password key maker

~~~text
keymake 32
~~~

keymake prompts twice without echo and streams exactly the requested number of
bytes into keymake.key. It accepts sizes from 1 through 20,000,000,000 and
refuses to overwrite an existing keymake.key.

The password and requested output size are processed with Argon2id v1.3 using
256 MiB of memory, four passes, and four lanes to derive a 64-byte root key.
SHAKE256 then expands that root as an XOF, so long output is not a repeated
short block. The same UTF-8 password and size always produce the same bytes.

Determinism means there is deliberately no random salt stored with the key:
attackers can recognize equal password-and-size inputs and perform offline
password guesses. Use a long, unique passphrase. For maximum-entropy cipher
keys, prefer keygen.

## Key text converters

~~~text
key2txt binary-key-file
txt2key decimal-text-file
~~~

key2txt streams a binary key into key2txt.txt as unsigned decimal byte values.
Every value is on its own line. A comma follows every value except the final
one, so a five-byte key is represented as:

~~~text
23,
255,
53,
9,
5
~~~

txt2key reverses this representation into txt2key.key. It requires exactly one
value from 0 through 255 per nonempty line. Plain lines without commas are also
accepted, as are CRLF line endings, surrounding ASCII spaces or tabs, and an
optional trailing comma. Signs, blank lines, multiple values on one line,
non-decimal data, more than three digits, and values above 255 are rejected.

Both tools stream in bounded memory, require the input filename to be in the
current directory, and refuse to overwrite their fixed output files. The text
representation exposes every secret key byte and must be protected just as
carefully as the original binary key.

## OTP tool

~~~text
otp file-to-process key-file
~~~

OTP is the one intentional in-place tool because its requested interface has no
output argument. It verifies that the key is at least as long as the input
before changing anything, streams both files in bounded memory, writes a
same-directory temporary file, syncs it, and atomically replaces only the named
input after revalidating that the pathname still identifies the file that was
opened. Running it again with the same key restores the original bytes.
Portable file APIs cannot make that identity check and pathname replacement one
indivisible operation, so do not run OTP in a directory concurrently writable
by an untrusted process.

OTP preserves Unix mode bits and the Windows read-only flag. Atomic replacement
cannot portably preserve ACLs, extended attributes, security labels, ownership,
timestamps, or other platform-specific metadata, so copy or restore those
separately when they matter. Symbolic-link inputs are rejected because replacing
a link would replace the link itself rather than its target.

For actual one-time-pad security, key bytes must be uniformly random, at least
as long as the message, kept secret, and never reused for any other message.
Reusing an OTP key destroys its security.

## Verification

To run the dedicated test suite for every executable, one binary at a time:

~~~text
.\test-each.bat
~~~

The runner is fail-fast. It starts a separate Cargo test target for each of the
21 binaries and uses one test thread inside each target. To run just one
binary's suite, name its bin-prefixed integration target directly; for example:

~~~text
cargo test --test bin_aes -- --test-threads=1
cargo test --test bin_keygen -- --test-threads=1
~~~

The broader library and cross-binary checks remain available through the usual
commands:

~~~text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --release --lib crypto::tests::production_password_kdf_round_trips -- --ignored --exact
cargo test --test tools keymake_is_deterministic_and_not_a_repeated_short_block -- --ignored --exact
~~~

The normal tests cover all eight key-file cipher round trips across chunk
boundaries and all eight password cipher round trips, wrong-password rejection,
fresh salts, authenticated password metadata, format separation, and the
standalone command wiring of every password binary. They also cover empty
files, fresh nonces, wrong keys, tampering, no-overwrite behavior, streamed OTP,
exact-size key generation, actual key2txt/txt2key process-level round trips,
converter buffer boundaries, accepted text variants, malformed input rejection,
and converter no-overwrite behavior. The explicitly ignored tests exercise a
complete password-file round trip at its production 512 MiB cost and run
keymake's full 256 MiB settings twice. They are separate so routine tests do not
make those large allocations.
