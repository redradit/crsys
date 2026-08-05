# Break the specification, not the code

There is a standing request in [SECURITY.md](SECURITY.md): CRSYS has no second
implementation, so no ambiguity in its format specification has ever been shaken
out by anything except this codebase reading its own mind. That is the largest
gap in the project, and it is not one the author can close.

**The challenge: write a decrypter for CRSYS containers from
[SPEC.md](SPEC.md) alone, without reading `crsys/`.**

Then check it against the nine frozen vectors. If it disagrees with them, one of
us is wrong. If you had to open the Python to get it working, **the
specification is the thing that failed, and that is the finding I want.**

This is a better-shaped request than "please review my cryptography", which is
hours of unpaid work with no clear finish line. This one is bounded, it has a
pass/fail condition you can check yourself without trusting me, and it does not
require you to take my word for anything.

## What you get

Everything needed is in [`tests/vectors.json`](tests/vectors.json). It is
self-contained: no code of mine has to run for you to use it. Verified — all nine
open using only the fields in that file.

```json
{
  "format": "CRSYS container",
  "version": 1,
  "identities": {
    "alice": {
      "secret_hex":  "…",   // 64 bytes: the private key material
      "public_hex":  "…",   // 64 bytes: x25519_pub(32) || ed25519_pub(32), §2.1
      "fingerprint": "13fa-d3d4-c0fe-7e09"
    }
  },
  "vectors": [
    {
      "name":          "signed-multi-chunk",
      "description":   "Four data chunks plus the signature trailer.",
      "recipients":    ["bob"],      // identities that must be able to open it
      "signer":        "alice",      // or null when unsigned
      "suite":         1,            // 1 = ChaCha20-Poly1305, 2 = AES-256-GCM
      "chunk_size":    1024,
      "armored":       false,        // true when container_b64 wraps ASCII armor
      "plaintext_hex": "…",          // what you must get out
      "container_b64": "…"           // the container, base64
    }
  ]
}
```

**The private keys in that file are published deliberately.** They protect
nothing and exist only so that other implementations can decrypt the vectors.
Never reuse them for anything.

The nine vectors, in the order I would attempt them:

| Vector | Why it is here |
|---|---|
| `unsigned-short` | The simplest thing that works. Start here. |
| `unsigned-empty` | Empty plaintext: the final chunk is the only chunk. |
| `unsigned-exact-chunk` | Plaintext exactly one chunk long. An off-by-one here is the classic mistake. |
| `signed-short` | Now the trailer, the signature, and what it covers. |
| `signed-multi-chunk` | Four chunks: the counter and the "final" flag in the nonce. |
| `aes256gcm` | Suite 2 instead of the default. |
| `multi-recipient` | Three envelopes over one payload; any one private key opens it. |
| `hidden-recipients` | Fingerprints zeroed, so you cannot look up your own stanza. |
| `armored` | ASCII armor around the same thing. |

Decrypt-only is enough. You never have to produce a container.

## What counts as a finding

In rough order of how much I want to hear about it:

1. **A place where SPEC.md let you build something wrong.** You followed it, your
   implementation disagreed with a vector, and re-reading the specification you
   can see it permitted your reading. This is the best possible outcome for the
   project and the worst for the specification.
2. **A place where you had to guess.** Two readings, no way to choose, and you
   picked by trial and error. Tell me which sentence, and both readings.
3. **A place where you had to read `crsys/`.** Note it, even if you resolved it
   in thirty seconds. A normative specification that requires the reference
   implementation is not normative. There used to be two such references in
   SPEC.md, both pointing at `crsys/keys.py` for a list of curve points; they are
   inlined now precisely because someone doing this would have hit them.
4. **A security property the specification describes but does not actually
   pin down.** §6 lists what a conformant implementation must reject; if you can
   write something that passes all nine vectors and is still insecure, that is a
   specification defect of the most serious kind.
5. **Anything that was simply tedious.** Friction is information too.

Not useful, in the interest of your time: style opinions about the Python,
whether Python was the right choice, or that the project should not exist because
`age` does. [SECURITY.md](SECURITY.md) already tells people to use `age` for
anything that matters, and says so in the first paragraph.

## Where to send it

Open an issue. Nothing here is sensitive by definition — the specification is
public and the keys are published — so there is no need for a private report
unless you find something that affects a real user, in which case
[SECURITY.md](SECURITY.md) says how.

A diff against SPEC.md is welcome and more useful than prose. So is a link to
your implementation, however rough, in whatever language: a second one existing
at all changes what this project can honestly claim about itself.

## What is in it for you

Not much, and I would rather say so than dress it up. There is no money, no
bounty, and about two hundred lines of work.

What there is: a self-contained protocol built out of standard primitives, a
specification short enough to read in one sitting, an unusually complete record
of the twelve defects already found and how each was caught, and a pass/fail
oracle so you never have to wonder whether you got it right. If you want to
practise implementing a hybrid encryption scheme against something with real test
vectors rather than a toy, this is that, and any ambiguity you find is a
contribution with your name on it.

If you get it working, say so even if you found nothing. **"The specification was
sufficient" is itself a result**, and right now the project cannot claim it.
