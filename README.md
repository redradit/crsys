# CRSYS — hybrid public-key encryption

[![CI](https://github.com/redradit/crsys/actions/workflows/ci.yml/badge.svg)](https://github.com/redradit/crsys/actions/workflows/ci.yml)

Encrypt and sign files and messages with a public/private key pair, from a
graphical interface or the command line.

```
X25519 (ECDH)  +  HKDF-SHA256  +  ChaCha20-Poly1305 / AES-256-GCM  +  Ed25519
```

## An honest premise

**The mathematical primitives are not invented here, and that is deliberate.** A
home-made cipher looks unbreakable to the person who wrote it and falls in hours
to anyone who does cryptanalysis for a living. There is no shortcut: a cipher's
strength comes from years of public attempts to break it.

What *is* custom in CRSYS is everything else — which is also where real systems
actually get broken:

- the container format and its framing;
- key encapsulation and multi-recipient handling;
- a chunked mode that resists truncation and reordering;
- the binding between a signature, the sender's identity and the recipient list;
- protection of the private key at rest.

The result: without the right private key there is no known way to read the
content, and every single modified bit is detected.

Before trusting it with anything important, read [SECURITY.md](SECURITY.md) —
in particular the "What it does not protect against" section.

## Install

```bash
pip install cryptography
```

For the graphical interface:

```bash
pip install customtkinter
```

Optional, for a stronger private-key KDF:

```bash
pip install argon2-cffi
```

When `argon2-cffi` is present Argon2id is used, otherwise scrypt (128 MiB,
~0.6 s). The key file records which one was used, so both configurations stay
mutually compatible.

## Graphical interface

```bash
python -m crsys_gui
```

On Windows you can also double-click `CRSYS.pyw` (no console window).
`python -m crsys_gui -k FOLDER` uses a keyring other than the default.

| Tab | What it does |
|---|---|
| **Identities** | Generate, import, export and delete keys. Shows the fingerprint and the compact form to send to whoever needs to write to you. |
| **Encrypt** | Text or file, for one or more recipients, optionally signed. |
| **Decrypt** | Opens a container and states plainly **who signed it**. |
| **Sign** | Detached signatures: the file stays in the clear, the signature travels separately. |

The **keyring** is a folder (`~/.crsys` by default) holding `name.key` /
`name.pub` pairs — the same files the command line uses, so both interfaces work
on the same material with no conversion.

Choices made so the GUI does not weaken what the CLI gives you:

- **Unlocked private keys stay in memory until you lock them.** Without a cache
  every operation would cost a passphrase prompt and a full KDF run, and an
  interface that asks ten times in a row pushes people towards short
  passphrases. The header always shows how many keys are unlocked with a button
  to lock them; after **10 minutes idle** they are dropped automatically, and
  closing the window drops them regardless.
- **Signature status is not a footnote.** Green only when the signature is valid
  *and* the fingerprint is in your keyring; amber when the message is unsigned,
  or when the signature is valid but from a key you do not know — because a
  valid signature from a stranger tells you nothing about who they are.
- **"Inspect container"** shows suite, recipients and whether it is signed
  without using any key and without decrypting anything.
- **Slow work runs off the GUI thread** with a progress bar, so the window stays
  responsive even on multi-gigabyte archives.

## Command line

### Generate an identity

```bash
python -m crsys keygen -o alice -c "Alice <alice@example.com>"
```

Creates `alice.key` (private, passphrase-protected) and `alice.pub` (public,
distribute freely). It also prints the **fingerprint**, which is what you verify
by voice or in person before trusting a key:

```
Fingerprint : ae76-a01c-cc36-c5a8
Compact form: crsys1yNVvKH6U-xsBFJ972kJJCE...
```

### Encrypt and sign

```bash
python -m crsys encrypt -r bob.pub -s alice.key -i contract.pdf -o contract.crsys
```

- `-r` is repeatable: one file readable by several recipients, encrypted once
- `-s` signs the content, so Bob knows for certain it came from Alice
- `--self` adds the sender as a recipient, to re-read what you sent
- `--armor` produces ASCII text you can paste into an email
- `--hide-recipients` zeroes the fingerprints in the header

### Decrypt

```bash
python -m crsys decrypt -k bob.key -i contract.crsys -o contract.pdf --require-signer alice.pub
```

`--require-signer` is the important part: without it, an unsigned message is
accepted silently. With it, the command fails (exit code 3) when the signature
is missing or belongs to somebody else.

### Everything else

```bash
python -m crsys inspect -i contract.crsys        # public metadata, no key needed
python -m crsys pubkey -k alice.key --compact    # public key on one line
python -m crsys fingerprint bob.pub              # fingerprint to verify by voice
python -m crsys sign   -k alice.key -i doc.pdf -o doc.sig    # detached signature
python -m crsys verify -i doc.pdf -S doc.sig                 # verify
python -m crsys passwd -k alice.key              # change the passphrase
```

Exit codes: `0` ok, `1` usage error, `2` cryptographic or format error,
`3` signature missing or mismatched.

For automation the passphrase can come from `--passphrase-file` or the
`CRSYS_PASSPHRASE` environment variable.

## Library

```python
from crsys import KeyPair, encrypt_bytes, decrypt_bytes, encrypt_file, decrypt_file

alice = KeyPair.generate()
bob = KeyPair.generate()

sealed = encrypt_bytes(b"message", recipients=[bob.public_key], signer=alice)
plaintext = decrypt_bytes(sealed, bob, expected_signer=alice.public_key)

# Files of any size, streaming
encrypt_file("video.mkv", "video.crsys", [bob.public_key], signer=alice)
res = decrypt_file("video.crsys", "video.mkv", bob, expected_signer=alice.public_key)
print(res.signer_fingerprint, res.plaintext_bytes)
```

`decrypt_bytes` and `decrypt_file` release the plaintext **only** once every
check passes; `decrypt_file` writes to a temporary file and renames it at the
end, so a tampered container leaves nothing partial behind.

`decrypt_stream` is the streaming API: it writes chunks as it authenticates
them, so the signature is only verified at the end. Use it knowing that.

## How it works

```
CEK <- random(32)                        content key, used exactly once

for each recipient R:
    eph       <- ephemeral X25519 key pair, new per recipient per message
    shared     = ECDH(eph_priv, R.x25519)
    KEK, nonce = HKDF-SHA256(shared, info = version | suite | eph_pub | R)
    envelope   = AEAD(KEK, nonce, CEK)

payload = STREAM-AEAD(CEK) over the plaintext, in 64 KiB chunks
trailer = Ed25519(sender) over  domain | sender | header | SHA-256(plaintext)
```

### Container format

```
off  len  field
0    4    magic          "CRSY"
4    1    version        0x01
5    1    suite          1 = ChaCha20-Poly1305   2 = AES-256-GCM
6    1    flags          bit0 = signed
7    1    reserved       0x00
8    4    chunk_size
12   32   cek_commit     commitment to the content key
44   2    n_recipients
46   ...  envelopes, 72 bytes each: fingerprint(8) | eph_pub(32) | wrapped CEK(48)

payload: a sequence of  uint32 length | ciphertext  chunks
         chunk i nonce  = counter(11 bytes) | final-chunk flag(1 byte)
         AAD of each chunk = the complete header
         final chunk    = signature trailer (128 bytes) or empty
```

[SPEC.md](SPEC.md) is the normative specification — enough detail to write an
independent implementation, with `tests/vectors.json` as the conformance suite.
The security properties this buys, and what does *not* follow from them, are
laid out in [SECURITY.md](SECURITY.md).

### Two version numbers, meaning different things

The **container format** is version 1: specified in SPEC.md, frozen by the test
vectors, and carried as a byte in every header. Changing it requires a new
version byte, and there is no plan to.

The **package** is 0.x. That is not modesty about the format — it reflects the
implementation being young. Eight defects have been found so far, four of them
by a fuzzer written after the code was already "finished", and the rate has not
flattened. The format can stay at v1 for years while the package works its way
to 1.0; they are separate namespaces on purpose.

## Tests

```bash
python tests/run_all.py
```

227 tests, about 20 seconds; 93% coverage of the library and 90% overall. Beyond
the happy paths they cover:

- **every single bit** of a container flipped (3 bits per byte, at every
  offset) — no modification may go unnoticed;
- **every possible truncation** of the file, byte by byte;
- chunks reordered, duplicated, removed; data appended;
- envelopes and payloads grafted in from another message;
- an attempt to re-address a signed message to a third party;
- an attempt to re-attribute a signature to another identity;
- hostile headers: zero recipients, 60000 recipients, absurd `chunk_size`,
  future version, unknown suite and flags, malformed length prefixes;
- wrong passphrase, KDF parameter downgrade, corrupted key file;
- the full CLI path including exit codes, pipe mode and the automation
  passphrase sources;
- **frozen wire-format vectors** (`tests/vectors.json`) that pin the container
  bytes, so a refactor cannot silently change a derivation label or a nonce;
- **the GUI driven from code**: a real window with the event loop pumped by
  hand and modal dialogs replaced by automatic answers. Covers the full
  encrypt→decrypt cycle for both text and files, the three signature states,
  inspection, idle auto-lock, and rejection of identity names that would escape
  the keyring folder;
- **the dialogs' own validation**, driven directly rather than stubbed out —
  name rules, passphrase confirmation, key parsing. This is the code that stops
  an identity name from escaping the keyring folder and a mistyped passphrase
  from locking someone out of their own key, and stubbing the dialogs had left
  all of it unexecuted;
- **the operations that touch private keys on disk** — importing a key file,
  re-encrypting one under a new passphrase, exporting, deleting — including the
  cancel path at every prompt, because these are the ones whose failure mode is
  unrecoverable.

### Fuzzing

```bash
python tests/test_fuzz.py --iterations 500000 --seed 1
```

A seeded, structure-aware mutation fuzzer covering the container, armor and
key-file parsers. Atheris has no Windows wheels, so it is self-contained; a
failure prints the seed needed to replay it. A short campaign runs as part of
the normal suite, and CI runs a long one weekly with a fresh seed.

The invariant is stronger than "must not crash". On a binary container, **any**
mutation that changes the bytes must be rejected — a success would mean part of
the container is malleable. Only `CrsysError` is permitted to escape; a
`ValueError` or `IndexError` reaching the caller means malformed input got into
code that assumed otherwise.

### Defects found so far

Eleven. The first eight came from testing rather than from reading the code; the
last three came from comparing the construction against RFC 9180 and the
published analysis of Ed25519, which no amount of testing would have surfaced.

1. the signature did not cover the X25519 half of the sender's identity, which
   allowed a valid signature to be re-attributed to a different fingerprint;
2. armored-block detection failed when the message was preceded by text — that
   is, in an ordinary email;
3. in the GUI, an exception inside a callback killed the polling loop, after
   which every operation hung with no explanation;
4. non-binary input was read without a size limit, so pointing the tool at a
   huge non-CRSYS file exhausted memory instead of failing fast;
5. `PublicKey.parse` fell through to a path lookup, so a NUL byte surfaced as
   `ValueError` and an odd name as `OSError`, both reaching the CLI as a
   traceback *(fuzzer)*;
6. an empty `kdf:` header raised `IndexError` instead of a format error
   *(fuzzer, via the new key-file corpus)*;
7. KDF cost parameters were bounded individually but not by resulting memory:
   scrypt with `n=2²²` and `r=32` asks for roughly 17 TB, turning a hostile key
   file into a denial of service on open;
8. Argon2 requires `m >= 8*p`; values inside their own ranges could still
   violate it, and argon2-cffi raised `HashingError` straight through the error
   contract *(fuzzer)*;
9. **a universal signature forgery.** With the Ed25519 identity point as the
   signer's public key, the signature `(R = identity, S = 0)` verifies for
   *every* message. The signer key is read from the container trailer, so an
   attacker chooses it, and OpenSSL verifies such signatures without complaint.
   Anyone could produce a container that reported a valid signature while
   holding no private key at all *(found by comparing against "Taming the many
   EdDSAs")*;
10. the GUI attributed a verified signature to a contact by matching the 64-bit
    fingerprint, which SPEC.md itself says must not decide anything. Combined
    with 9, a feasible grind produced a forged key whose fingerprint matched a
    real contact — full impersonation in the interface. Identity is now decided
    on all 64 bytes;
11. the X25519 shared secret was never checked for the all-zero value, which
    RFC 9180 §7.1.4 makes a MUST. OpenSSL happens to refuse those points, so
    nothing was exploitable — but SPEC.md documented only an input blocklist, so
    an independent implementation following it with a laxer backend would have
    been insecure *and* conformant.

## Layout

```
crsys/                 library and command line
  keys.py              key pairs, fingerprints, key file formats
  container.py         binary header and validation
  core.py              encapsulation, STREAM payload, signatures
  suite.py             selectable AEADs and nonce construction
  kdf.py               Argon2id / scrypt for the passphrase
  armor.py             ASCII armor (streaming capable)
  cli.py               command line
crsys_gui/             graphical interface
  keyring.py           key folder and unlocked-key cache
  tasks.py             background work with Tk-safe callbacks
  widgets.py           reusable components
  dialogs.py           modal windows
  tab_*.py             the four panels
  app.py               main window
tests/
  run_all.py           suite runner
  test_fuzz.py         mutation fuzzer (also runs standalone)
  vectors.json         frozen wire-format vectors
  make_vectors.py      regenerates them, deliberately never run by the suite
SPEC.md                normative format specification
SECURITY.md            threat model and known limitations
CRSYS.pyw              double-click launcher for the GUI
```

## License

MIT — see [LICENSE](LICENSE).
