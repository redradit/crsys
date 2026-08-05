# Changelog

Notable changes per release. Every entry states what happened to the **wire
format**, because that is the one thing that can strand a file someone already
encrypted.

Two version numbers move independently here, and the distinction matters — see
[README](README.md#two-version-numbers-meaning-different-things). The package
version is below. The container format version is `1` and has never changed.

## 0.2.1 — 2026-08-05

Three interface defects, all found by opening the application and using it
rather than by any test. The library and the wire format are untouched.

### Fixed

- **The warning under "Sign with" contradicted the control above it.** It was a
  fixed string, so selecting a signer left "Unsigned, the recipient can read it
  but cannot prove you wrote it." sitting directly beneath that signer's name.
  A user who trusted it would believe an unsigned message was going out when it
  was signed, or the reverse — and [SECURITY.md](SECURITY.md) specifically
  advises sending *unsigned* when you would not want a message attributable to
  you. The hint now follows the selection, and the signed branch warns about the
  half people do not expect: a CRSYS signature is non-repudiable, so anyone the
  recipient shows it to can also verify it.

  Nothing had ever asserted on that text, which is why it survived every run of
  a 289-test suite. Six tests now cover it, including one that drives the
  dropdown's own callback rather than setting the value around it, and one that
  checks a keyring refresh does not leave the text stale.

- **Paste did nothing, and said nothing, when the clipboard held no text.** The
  handler swallowed the `TclError` silently, so the button looked broken. It now
  reports in the status bar, and a failed paste no longer looks like a paste of
  nothing.

- **The Encrypt button was cut in half at the default window size.** The panel's
  side column did not fit in 1120×740, so the primary action of the panel was
  clipped by the window edge until you resized. The default is now 1120×820 and
  the minimum moves with it, since a geometry saved by an older version would
  otherwise restore the same clipping.

  Honest note on this one: the *defect* is confirmed — there is a screenshot of
  the button cut through the glyphs. The *fix* is not visually confirmed. A
  Windows system window took the foreground partway through the session and
  blocked further input, and two attempts to measure the layout
  programmatically returned nonsense because Tk gives unmapped widgets no
  geometry. The change is small and in the right direction, but it deserves a
  glance from a human before anyone calls it verified.

### Wire format

**Unchanged.** Container version `1`, key file version `1`. No file in `crsys/`
was touched by this release.

## 0.2.0 — 2026-08-04

**Security release. It fixes a universal signature forgery present in 0.1.0.**

### Fixed — security

- **A universal signature forgery.** With the Ed25519 identity point as the
  signer's public key, the signature `(R = identity, S = 0)` satisfies the
  verification equation for *every* message. The signer's key is read from the
  container trailer, so an attacker chooses it, and OpenSSL both accepts such
  keys and verifies such signatures. Anyone could produce a container that
  reported a valid signature while holding no private key at all. All eight
  small-order Ed25519 encodings are now refused when a public key is
  constructed — CRSYS cannot change what OpenSSL verifies, so it refuses the
  key instead.
- **Signature attribution by fingerprint.** The GUI matched a verified
  signature to a contact using the 64-bit fingerprint, which
  [SPEC.md](SPEC.md) itself says must not decide anything. Combined with the
  forgery above, a feasible grind produced a forged key whose fingerprint
  matched a real contact — full impersonation in the interface. Identity is now
  decided on all 64 bytes of the public key.
- **The X25519 shared secret was never checked for the all-zero value**, which
  RFC 9180 §7.1.4 makes a MUST. OpenSSL happens to reject those points, so
  nothing was exploitable in this implementation — but SPEC.md documented only
  an input blocklist, so an independent implementation following the
  specification with a laxer backend would have been insecure *and* conformant.
- **Private key files were not actually restricted on Windows.** `os.chmod`
  there only toggles the read-only flag, so a key file kept whatever the
  containing directory granted. The ACL is now rewritten with `icacls` to drop
  inheritance and grant the creating account alone, identified by SID rather
  than by name. The result is proven by reading the file back and rolled back if
  that fails: a key nobody can open would be worse than one whose permissions
  are merely wide.

### Fixed

- The Import menu in the Identities panel appeared but choosing an entry did
  nothing. A hand-rolled popup destroyed itself on mouse-down; it is now a real
  `tkinter.Menu`.
- Streaming decryption and several GUI paths gained tests that cover what was
  previously only asserted in prose.

### Changed

- The interface was redesigned: its own palette, a real type and spacing scale,
  and far less explanatory text on screen.
- **Documentation correction, not a code change.** SPEC.md presented
  `cek_commit` as if it repaired the AEAD not being key-committing. Validating
  that the right content key was unwrapped and binding the key to the message
  are different properties, and only the first is present. Raised by a reviewer
  on Cryptography Stack Exchange.

### Added — tooling

- `ruff` and `mypy`, blocking in CI, both clean. Configuration in
  `pyproject.toml`, curated rather than maximal, with a reason beside every rule
  family left out.
- Test failures now name their cause. Exceptions raised inside a task callback
  are swallowed by design in the application, which under test meant a wait
  reported a timeout and blamed the clock; they are now surfaced immediately.
  Wait budgets moved to `CRSYS_TEST_TIMEOUT` after a CI job was observed running
  ten times slower than usual on an unchanged commit.
- Per-test timings on every run, and `timeout-minutes` on every CI job.

### Wire format

**Unchanged.** Container version `1`, key file version `1`. Verified rather than
assumed: a container produced by the 0.1.0 code decrypts correctly under this
release, and `tests/vectors.json` still pins the bytes.

The small-order key rejection changes which *keys* are accepted, not which
containers are valid. Anything you could encrypt or decrypt before, you still
can — unless the key involved was one of the eight forgery-enabling encodings,
which no honest keygen produces.

## 0.1.0 — 2026-08-02 — **withdrawn, do not use**

First tagged release. **It contains the universal signature forgery described
above.** A signature verdict from this version cannot be trusted: a container
can claim to be signed by anyone.

Confidentiality and integrity are unaffected — the payload encryption has no
known weakness in this version, and a modified container is still detected.
What cannot be relied on is *who wrote it*.

Anyone running it should upgrade. Files encrypted with it stay readable; the
format did not change.
