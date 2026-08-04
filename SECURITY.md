# Security

## Do not use release 0.1.0

The only release tagged so far, `v0.1.0`, **contains a universal signature
forgery**: with the Ed25519 identity point as the signer's key, one fixed
signature verifies every message, so a container from that version can claim to
be signed by anyone. The fix landed thirteen commits after the tag and was never
released, which is a release-management failure and is recorded as such in the
[changelog](CHANGELOG.md).

Confidentiality and integrity are unaffected in 0.1.0, and files encrypted with
it stay readable — the format did not change. What cannot be trusted is any
signature verdict it gives you.

## Status

CRSYS has **not been independently audited**. It was written carefully, it uses
only standard primitives, and it has a test suite that deliberately attacks it —
but that is not the same thing as review by people whose job is breaking things.

Twelve findings so far. Four came from the mutation fuzzer; two of the most
serious came from reading RFC 9180 and the EdDSA literature and checking what the
code actually did against them, not from testing at all. They are listed in the
[README](README.md#defects-found-so-far).

That record is the argument for an audit, not against one. The worst of them was
a universal signature forgery that had survived every test, every fuzzing
campaign, and repeated readings of the code, and was found only by comparing the
construction against published analysis of Ed25519.

The twelfth is the most instructive. A reviewer on Cryptography Stack Exchange
pointed out that this very document was claiming a stronger property than the
code provides: validating that the right content key was unwrapped is not the
same as binding the key to the message. It took one outside expert about a day to
find an overstated security claim here. There is no reason to believe that
process is finished.

For data whose compromise would have serious consequences, use
[age](https://age-encryption.org) or GnuPG. Their value is not the algorithm; it
is the number of competent people who have tried to break them and failed.

## Design summary

| Layer | Choice |
|---|---|
| Key agreement | X25519 (ECDH), fresh ephemeral key per recipient per message |
| Key derivation | HKDF-SHA256, domain-separated, binding both public keys |
| Payload | ChaCha20-Poly1305 or AES-256-GCM, STREAM mode, 64 KiB chunks |
| Signatures | Ed25519, covering signer identity, header and plaintext hash |
| Key at rest | Argon2id (128 MiB, t=3, p=4) or scrypt (N=2¹⁷, r=8, p=1) |

No cryptographic primitive is implemented in this repository. Everything comes
from [pyca/cryptography](https://cryptography.io), which is backed by OpenSSL.

## What it protects against

| Property | Mechanism |
|---|---|
| Confidentiality | X25519 ECDH with a per-message ephemeral key; 256-bit random content key |
| Semantic security | New ephemeral key every time, so two encryptions of the same file are uncorrelated |
| Integrity | AEAD tag on every chunk; the header is the AAD of all chunks |
| Non-malleable header | Changing suite, `chunk_size` or the recipient list invalidates the whole payload |
| Truncation resistance | The "final chunk" flag lives in the nonce, so cutting the tail breaks the last tag |
| Reordering resistance | The chunk counter lives in the nonce |
| Sender authenticity | Ed25519, with the signature also covering the header |
| Anti-surreptitious-forwarding | The signature covers the recipient list, so a recipient cannot re-address the message |
| Anti-identity-substitution | The signature covers the signer's *whole* public key, not just the Ed25519 half used to verify it |
| Content key validation | `cek_commit` forces every recipient onto the same content key, which closes the multi-recipient case of invisible salamanders. It is **not** full key-committing security — see [SPEC.md §3.3](SPEC.md) for what it does and does not give |
| No nonce reuse | Nonces are derived or counted, never random, under a key used exactly once |
| KDF downgrade resistance | The scrypt/Argon2 parameters in the key file are AAD |
| Degenerate keys rejected | X25519 output checked for all-zero (RFC 9180 §7.1.4); small-order Ed25519 keys refused, closing a universal forgery |
| Identity decided on full keys | A verified signature is attributed to a contact by comparing all 64 bytes, never by the 64-bit fingerprint |
| Bounded resource use | Header fields are validated before any allocation; KDF parameters are bounded by resulting memory, not just per-parameter; armored input is capped |

An attacker holding only the ciphertext has no known path in: it would require
breaking X25519 or ChaCha20-Poly1305. An attacker who can modify the file is
always detected — the test suite flips every bit of a container and truncates it
at every byte offset, and every single case is rejected.

## What it does not protect against

These are the things that actually get systems broken, so they are listed first
and plainly.

**Trust distribution.** There is no PKI and no web of trust. If someone hands
you a public key while claiming to be Bob, you will encrypt to them. **Verify
fingerprints over a separate channel.** This is the one link the software cannot
close for you.

**A valid signature from an unknown key means nothing.** It proves the holder of
*some* private key signed the message — not who they are. Always pin the
expected signer (`--require-signer`, or the "Expected sender" field in the GUI)
rather than trusting whatever identity the message carries.

**Forward secrecy.** If a long-term private key is compromised, every past
message an attacker retained becomes readable. Achieving forward secrecy needs a
ratchet protocol (like Signal's) and interactive sessions — a different design.

**Post-quantum security.** X25519 and Ed25519 do not resist a
cryptographically-relevant quantum computer. Anyone whose threat model includes
"harvest now, decrypt later" needs a hybrid with ML-KEM.

**Metadata.** File size, timing and recipient count are all visible.
`--hide-recipients` conceals *who*, not *how many*.

**Replay and freshness.** There are no timestamps, sequence numbers or expiry. A
valid container stays valid forever and can be re-delivered later. If that
matters for your use case, put freshness inside the plaintext.

**Deniability — signing gives you the opposite.** This is a property, not a gap,
but it is easy to get wrong by accident so it is stated plainly.

A signed CRSYS message is **non-repudiable**. The recipient can decrypt it and
hand the plaintext, the signature and your public key to anyone, who can then
verify that you wrote it. That is what a signature is for, and for a contract or
a release artifact it is exactly right.

It is often the wrong default for correspondence. RFC 9180's HPKE takes the
other route: its `mode_auth` authenticates the sender with a static-ephemeral
Diffie-Hellman, so the recipient is convinced but cannot transfer that
conviction to a third party — either party could have produced the same
transcript. CRSYS deliberately does not offer that mode.

If you would not want a message attributable to you in front of somebody else,
send it unsigned. The recipient still gets confidentiality and integrity; what
they lose is proof of authorship, which in that situation is the point.

**A compromised endpoint.** Keyloggers and malware beat any encryption.

## Known implementation weaknesses

Honest list of things a reviewer would flag:

1. **Python cannot reliably erase memory.** Private keys and passphrases live in
   immutable `bytes` and `str` objects that cannot be zeroed, may be copied by
   the garbage collector, and can be paged to swap or captured in a crash dump.
   This is inherent to the language, not fixable in this codebase.

2. **The GUI caches unlocked private keys in RAM.** This is a deliberate
   usability trade-off — see the README — mitigated by a visible unlocked-key
   count, a manual lock button, a 10-minute idle auto-lock, and locking on exit.
   It is still a wider exposure window than the CLI, which holds a key only for
   the duration of one command.

3. **Timing side channels are not addressed at the Python level.** In
   particular, `_decapsulate` tries the matching envelope first, so decryption
   time can reveal which recipient you are to a local observer. Comparisons of
   secret values do use constant-time primitives.

4. **File permissions are enforced, but verify them if it matters to you.**
   Private key files are created with mode `0600` on POSIX. On Windows that
   would be nearly meaningless — `os.chmod` only toggles the read-only flag — so
   the ACL is rewritten with `icacls` to drop inheritance and grant the creating
   account alone. The account is identified by SID rather than by name, because
   a name can be ambiguous, and the result is proven by reading the file back
   and rolled back if that fails: a key nobody can open would be worse than one
   whose permissions are merely wide. `keygen` says so explicitly when the file
   could not be narrowed.

   This protects against other accounts on the same machine. It does nothing
   about backups, and nothing about a keyring placed in a synced folder — put
   one in OneDrive, Dropbox or iCloud and the private key is uploaded, ACL and
   all. The default location, `~/.crsys`, is not normally synced.

5. **Streaming decryption releases unverified plaintext.** `decrypt_stream`
   writes authenticated chunks as they arrive, so the signature is only checked
   at the end. `decrypt_file` and `decrypt_bytes` do not have this property —
   they publish the result only after every check passes. Use those unless you
   specifically need streaming.

6. **No second implementation.** [SPEC.md](SPEC.md) defines the format
   normatively and `tests/vectors.json` provides frozen conformance vectors, so
   an independent implementation is now possible to write and check. Until
   somebody writes one, no specification ambiguity has been shaken out by
   anything other than this codebase reading its own mind.

7. **Supply chain.** Security depends on `cryptography` (and OpenSSL beneath
   it), plus `argon2-cffi` when present. That is a strength — those are audited —
   but it is still a dependency surface.

## Passphrase strength

The private key file is only as strong as the passphrase protecting it. Both
KDFs are memory-hard, costing roughly 128 MiB and half a second per guess on one
core, which pushes GPU and ASIC attacks from "trivial" to "expensive". That is a
large multiplier, but a multiplier cannot rescue a guessable passphrase.

| Passphrase | Rough entropy | Verdict |
|---|---|---|
| Human-chosen 8 characters | ~25 bits | Falls in hours. Do not use. |
| Random 10 characters, mixed | ~60 bits | Strong |
| 4 random words (diceware) | ~52 bits | Strong |
| 6 random words (diceware) | ~78 bits | Strong for any realistic adversary |

Entropy figures assume the words or characters are chosen *randomly*, not by a
human. A memorable phrase you invented yourself has far less entropy than its
length suggests.

## Reporting a vulnerability

Open an issue for anything non-sensitive. For a finding that would put existing
users at risk, please report it privately first through GitHub's security
advisory feature rather than in a public issue.

Findings against the protocol design are especially welcome — that is the part
of this project that has not been reviewed by anyone else.
