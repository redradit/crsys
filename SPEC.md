# CRSYS container format — specification v1

This document defines the CRSYS wire format precisely enough to write an
independent implementation. It is normative; where it and the Python code
disagree, that is a bug in one of them, and `tests/vectors.json` decides.

The key words MUST, MUST NOT, SHOULD and MAY are used in the RFC 2119 sense.

Status: **stable for version 1**. Any change to the byte layout, the derivation
labels or the nonce construction requires a new `version` byte.

---

## 1. Notation and primitives

All integers are **big-endian**. `||` is concatenation. `a[i:j]` is a byte slice,
half-open.

| Name | Definition |
|---|---|
| `X25519(sk, pk)` | RFC 7748 Diffie-Hellman, 32-byte output |
| `Ed25519_sign / _verify` | RFC 8032, 64-byte signature, 32-byte key |
| `HKDF(ikm, L, info)` | RFC 5869 with SHA-256, **empty salt**, output length `L` |
| `SHA256(m)` | FIPS 180-4 |
| `AEAD_Enc(k, n, p, a)` | Suite-dependent, 16-byte tag appended to the ciphertext |
| `random(n)` | Cryptographically secure random bytes |

### 1.1 Cipher suites

| id | AEAD | key | nonce | tag |
|---|---|---|---|---|
| `0x01` | ChaCha20-Poly1305 (RFC 8439) | 32 | 12 | 16 |
| `0x02` | AES-256-GCM | 32 | 12 | 16 |

An implementation MUST support suite `0x01`. Suite `0x02` is OPTIONAL to
implement but MUST be rejected cleanly if unsupported. Any other value MUST be
rejected.

### 1.2 Domain separation labels

Every label is an ASCII string terminated by one `0x00` byte. Implementations
MUST use these exact bytes.

| Constant | Value |
|---|---|
| `LABEL_KEM` | `"CRSY-v1-kem\x00"` |
| `LABEL_WRAP` | `"CRSY-v1-wrap\x00"` |
| `LABEL_COMMIT` | `"CRSY-v1-commit\x00"` |
| `LABEL_SIGN` | `"CRSY-v1-sign\x00"` |
| `LABEL_DETACHED` | `"CRSY-v1-detached\x00"` |
| `LABEL_FPR` | `"CRSY-fpr-v1\x00"` |
| `LABEL_KEYFILE` | `"CRSY-keyfile-v1\x00"` |

---

## 2. Identities

An identity is two independent key pairs:

* an **X25519** pair, used only for key agreement;
* an **Ed25519** pair, used only for signatures.

Reusing one key for both roles is a known source of cross-protocol attacks and
MUST NOT be done.

### 2.1 Public key encoding

```
public_key = x25519_pub(32) || ed25519_pub(32)          // 64 bytes
```

An implementation SHOULD reject an `x25519_pub` that is one of the well-known
small-order points of Curve25519 (the twelve-value list used by libsodium; see
`crsys/keys.py`), as an early and clear error on obviously bad key material.

This is a convenience, not the security control. RFC 7748 requires masking the
high bit of the u-coordinate before use, after which several entries in that
list are ordinary points, and no blocklist of encodings can be complete. The
control that matters is the output check in §3.2, which an implementation MUST
perform.

### 2.2 Private key encoding

```
secret = x25519_scalar(32) || ed25519_seed(32)          // 64 bytes
```

The X25519 scalar is used as-is; RFC 7748 clamping is applied internally by the
X25519 function. The Ed25519 seed is the 32-byte seed of RFC 8032, not the
expanded key.

### 2.3 Fingerprint

```
fingerprint = SHA256(LABEL_FPR || x25519_pub || ed25519_pub)[0:8]
```

Displayed as lowercase hex in four dash-separated groups of four:
`a1b2-c3d4-e5f6-0718`. The fingerprint is a **display and lookup aid only**. It
MUST NOT be used as a security decision on its own — 64 bits is not
collision-resistant. Comparisons that matter MUST use the full 64-byte key.

---

## 3. Container

```
container = header || payload
```

### 3.1 Header

```
offset  size  field
0       4     magic          = "CRSY" (0x43 0x52 0x53 0x59)
4       1     version        = 0x01
5       1     suite          cipher suite id
6       1     flags          bit0 = signed; all other bits MUST be 0
7       1     reserved       MUST be 0x00
8       4     chunk_size     uint32, plaintext bytes per non-final chunk
12      32    cek_commit     commitment to the content key (§3.3)
44      2     n_recipients   uint16, MUST be >= 1
46      ...   recipients     n_recipients * 72 bytes

header_len = 46 + 72 * n_recipients
```

Each recipient stanza is:

```
offset  size  field
0       8     fingerprint    recipient fingerprint, or 8 zero bytes if hidden
8       32    eph_pub        ephemeral X25519 public key, unique per stanza
40      48    wrapped_cek    AEAD ciphertext of the 32-byte CEK (32 + 16 tag)
```

Receivers MUST enforce, before doing any cryptographic work:

* `magic == "CRSY"`, `version == 0x01`, `reserved == 0x00`;
* `suite` is a supported value;
* `flags` has no bit set other than bit0;
* `1024 <= chunk_size <= 16777216`;
* `1 <= n_recipients <= 1024`;
* the declared stanza bytes are actually present.

`chunk_size` and `n_recipients` are attacker-controlled and are multiplied by
buffer sizes. An implementation MUST validate them **before** allocating.

### 3.2 Key encapsulation

For each recipient `R`, with a **fresh** ephemeral key pair per recipient per
message:

```
eph_sk       = random scalar
eph_pub      = X25519_base(eph_sk)
shared       = X25519(eph_sk, R.x25519_pub)
info         = LABEL_KEM || version(1) || suite(1) || eph_pub(32) || R.public_key(64)
okm          = HKDF(shared, 44, info)
kek          = okm[0:32]
kek_nonce    = okm[32:44]
wrapped_cek  = AEAD_Enc(kek, kek_nonce, CEK, LABEL_WRAP)
```

Binding both public keys into `info` is what rules out unknown-key-share
attacks. Because `kek` is used for exactly one encryption, `kek_nonce` being
derived rather than random is safe.

**An implementation MUST check that the X25519 output is not the all-zero value
and abort if it is**, matching RFC 9180 §7.1.4. `eph_pub` is read from a header
an attacker writes; if it is a low-order point the "shared secret" is a constant
the attacker knows. Rejecting small-order points on input is not a substitute —
the check belongs on the output, because a blocklist of encodings cannot be
complete. Some libraries (OpenSSL among them) already refuse these internally,
but an implementation must not depend on that.

A single `CEK = random(32)` is shared by all stanzas of one container.

Decapsulation reverses this. A receiver SHOULD try the stanza whose fingerprint
matches first, then the others, so that containers with hidden recipients still
open.

### 3.3 Content key commitment

```
cek_commit = HKDF(CEK, 32, LABEL_COMMIT)
```

After recovering a candidate CEK, a receiver MUST recompute this and compare it
against the header field in constant time, and MUST abort on mismatch.

Neither ChaCha20-Poly1305 nor AES-GCM is key-committing. Without this field an
attacker who knows two private keys can build one container that decrypts to two
different valid plaintexts depending on which key opens it (the "invisible
salamanders" attack).

### 3.4 Payload

The payload is a sequence of framed chunks:

```
chunk = length(4) || ciphertext(length)
```

where `length` is a uint32 counting the ciphertext bytes including the tag.
Receivers MUST reject `length < 16` and `length > chunk_size + 16`.

Chunks are encrypted in STREAM form:

```
nonce(i, final) = uint(i, 11 bytes) || (0x01 if final else 0x00)
ciphertext_i    = AEAD_Enc(CEK, nonce(i, final), plaintext_i, header)
```

* `i` starts at 0 and increments by 1 per chunk;
* **the AAD of every chunk is the complete header, all `header_len` bytes**;
* non-final chunks carry exactly `chunk_size` plaintext bytes, except that the
  last data chunk MAY be shorter;
* the **final chunk is always the trailer** (§3.5), never message data. A
  container therefore always has at least one chunk.

The counter in the nonce prevents reordering and duplication; the final flag
prevents truncation, because removing trailing chunks changes which chunk is
last and the tag no longer verifies.

A receiver determines `final` by lookahead: read a chunk, then attempt to read
the next. If none follows, the chunk just read is the final one. A truncated
file therefore fails authentication rather than yielding a shorter plaintext.

### 3.5 Trailer

The final chunk's plaintext is:

* **128 bytes** when `flags` bit0 is set:

```
trailer = signer_public_key(64) || signature(64)
signature = Ed25519_sign(signer_ed25519_sk,
                         LABEL_SIGN || signer_public_key(64) || header || SHA256(plaintext))
```

* **empty** when bit0 is clear.

`SHA256(plaintext)` is over the concatenated plaintext of the data chunks only,
excluding the trailer.

A receiver MUST reject a signed container whose trailer is not exactly 128
bytes, and MUST reject an unsigned container whose trailer is non-empty.

Three properties depend on the exact signed input, and an implementation that
omits any of them is not conformant:

1. `header` is covered, and the header contains the recipient list, so a
   recipient cannot re-address a signed message to somebody else and have the
   signature still verify (surreptitious forwarding).
2. `signer_public_key` is covered **in full**, both halves. Only the Ed25519
   half participates in verification, so without this an attacker could replace
   the X25519 half and make a genuine signature appear to come from a different
   fingerprint.
3. The trailer lives inside the AEAD, so the sender's identity is confidential
   against a passive observer.

If the caller supplied an expected signer, the recovered `signer_public_key`
MUST be compared against it in constant time, over all 64 bytes.

---

## 4. ASCII armor

```
-----BEGIN CRSYS MESSAGE-----
<standard base64 of the container, wrapped at 76 characters>
-----END CRSYS MESSAGE-----
```

Decoders MUST locate the markers anywhere in the input and ignore everything
outside them, so a container pasted into an email survives. Line breaks inside
the body are not significant. Decoders SHOULD bound the amount of text they
buffer; this implementation refuses armored input above 64 MiB.

Detached signatures use `-----BEGIN CRSYS SIGNATURE-----` with a 128-byte body:

```
body      = signer_public_key(64) || signature(64)
signature = Ed25519_sign(sk, LABEL_DETACHED || signer_public_key(64) || SHA256(data))
```

---

## 5. Key files

Text, with `key: value` headers, one blank line, then wrapped base64.

```
-----BEGIN CRSYS PRIVATE KEY-----
version: 1
cipher: chacha20poly1305        (or "none")
kdf: argon2id m=131072,p=4,t=3  (or "scrypt n=131072,p=1,r=8")
salt: <base64, >= 8 bytes>
nonce: <base64, 12 bytes>
fingerprint: a1b2-c3d4-e5f6-0718

<base64 of the 64-byte secret, encrypted unless cipher is "none">
-----END CRSYS PRIVATE KEY-----
```

The wrapping key is `KDF(passphrase, salt)`, 32 bytes. The AAD is:

```
LABEL_KEYFILE || "version=<v>\ncipher=<c>\nkdf=<k>\nsalt=<s>\nnonce=<n>\nfingerprint=<f>"
```

with the fields in exactly that order and the values exactly as they appear in
the headers. `comment` is deliberately excluded so it can be edited freely.

Because the KDF name and cost parameters are inside the AAD, an attacker cannot
weaken them and still have the file decrypt.

KDF parameters are attacker-controlled. An implementation MUST bound them by
**resulting memory**, not only per-parameter: scrypt's cost is `128*n*r`, so
values individually in range can multiply out to terabytes. This implementation
refuses anything above 1 GiB.

### 5.1 Compact public key

```
crsys1 || base64url_nopad( public_key(64) || SHA256("crsys1" || public_key)[0:4] )
```

The 4-byte checksum catches transcription errors. It is not a security control.

---

## 6. Conformance

An implementation is conformant if it decrypts every vector in
`tests/vectors.json` to the stated plaintext, reports the stated signer, and
rejects each of the following:

* any single-bit modification anywhere in a container;
* truncation at any offset;
* chunks reordered, duplicated or removed;
* a stanza or payload transplanted from another container;
* a header field outside the ranges in §3.1;
* a `cek_commit` that does not match the recovered CEK;
* a signed container whose signature does not cover the header, the full signer
  public key, and the plaintext hash.

Rejection MUST be a clean, typed error. A malformed input reaching code that
assumed well-formedness — surfacing as an index error, a struct error or an
out-of-memory kill — is a conformance failure, not merely a bug.

---

## 7. What this format deliberately does not do

Stated here so implementers do not assume otherwise: there is no forward
secrecy, no replay or freshness protection, no post-quantum resistance, no
padding (so plaintext length is revealed within one chunk), and no identity
binding beyond the raw key — fingerprint verification is out of band and out of
scope. See [SECURITY.md](SECURITY.md).
