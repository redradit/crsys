"""Regenerate tests/vectors.json.

Run this ONLY when the container format changes on purpose. The committed
vectors are what pins the wire format: if a refactor silently alters a
derivation label, a nonce, or the AAD, the vector tests fail — which is the
whole point. Regenerating to make a failure go away would destroy that.

    python tests/make_vectors.py

The private keys written here are published deliberately: they exist so other
implementations can decrypt the vectors. They protect nothing.
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crsys import (  # noqa: E402
    SUITE_AES256GCM,
    SUITE_CHACHA20POLY1305,
    KeyPair,
    encrypt_bytes,
)
from crsys.container import DEFAULT_CHUNK_SIZE  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")


def main() -> int:
    people = {name: KeyPair.generate(comment=name.capitalize())
              for name in ("alice", "bob", "carol")}

    identities = {
        name: {
            "secret_hex": kp.secret_bytes().hex(),
            "public_hex": kp.public_key.to_bytes().hex(),
            "fingerprint": kp.fingerprint_hex,
        }
        for name, kp in people.items()
    }

    plans = [
        ("unsigned-empty", "Empty plaintext, default suite. The final chunk is "
                           "the only chunk.", ["bob"], None, SUITE_CHACHA20POLY1305,
         DEFAULT_CHUNK_SIZE, b"", False),
        ("unsigned-short", "Single short chunk.", ["bob"], None,
         SUITE_CHACHA20POLY1305, DEFAULT_CHUNK_SIZE, b"hello world", False),
        ("signed-short", "Signed by alice; the trailer carries her public key "
                         "and signature.", ["bob"], "alice", SUITE_CHACHA20POLY1305,
         DEFAULT_CHUNK_SIZE, b"signed message", False),
        ("unsigned-exact-chunk", "Plaintext exactly one chunk long, so the last "
                                 "data chunk is full size.", ["bob"], None,
         SUITE_CHACHA20POLY1305, 1024, b"A" * 1024, False),
        ("signed-multi-chunk", "Four data chunks plus the signature trailer.",
         ["bob"], "alice", SUITE_CHACHA20POLY1305, 1024, b"B" * 3500, False),
        ("aes256gcm", "Suite 2 instead of the default.", ["bob"], "alice",
         SUITE_AES256GCM, 1024, b"aes payload" * 40, False),
        ("multi-recipient", "Three envelopes over one payload; any of the three "
                            "private keys opens it.", ["bob", "alice", "carol"],
         "alice", SUITE_CHACHA20POLY1305, 1024, b"for all three", False),
        ("hidden-recipients", "Recipient fingerprints zeroed in the header.",
         ["bob", "carol"], None, SUITE_CHACHA20POLY1305, DEFAULT_CHUNK_SIZE,
         b"anonymous envelope", False),
        ("armored", "ASCII armored form of an otherwise ordinary container.",
         ["bob"], "alice", SUITE_CHACHA20POLY1305, 1024, b"armored payload", True),
    ]

    vectors = []
    for (name, description, recipients, signer, suite, chunk_size,
         plaintext, armored) in plans:
        blob = encrypt_bytes(
            plaintext,
            recipients=[people[r].public_key for r in recipients],
            signer=people[signer] if signer else None,
            suite=suite,
            chunk_size=chunk_size,
            hide_recipients=(name == "hidden-recipients"),
            armored=armored,
        )
        payload = blob.encode("ascii") if isinstance(blob, str) else blob
        vectors.append({
            "name": name,
            "description": description,
            "recipients": recipients,
            "signer": signer,
            "suite": suite,
            "chunk_size": chunk_size,
            "armored": armored,
            "plaintext_hex": plaintext.hex(),
            "container_b64": base64.b64encode(payload).decode("ascii"),
        })

    document = {
        "format": "CRSYS container",
        "version": 1,
        "warning": "TEST VECTORS ONLY. The private keys below are published on "
                   "purpose so other implementations can decrypt these vectors. "
                   "They protect nothing. Never reuse them.",
        "identities": identities,
        "vectors": vectors,
    }

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(document, fh, indent=2, sort_keys=False)
        fh.write("\n")

    print("wrote %s: %d identities, %d vectors"
          % (OUT, len(identities), len(vectors)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
