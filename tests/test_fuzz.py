"""Structure-aware mutation fuzzing of the container, armor and key-file parsers.

Atheris has no Windows wheels, so this is a self-contained mutation fuzzer. It
is seeded and therefore reproducible: a failure prints the seed and iteration
needed to replay it.

The invariant is stronger than "must not crash":

* **binary container** -- if the mutated bytes differ from the original, decryption
  MUST fail. A success would mean part of the container is malleable, which is
  exactly what the header-as-AAD design is supposed to rule out;
* **armored text** -- mutations may be benign (line breaks, text outside the
  markers), so a success is allowed but the plaintext must match exactly;
* **any parser** -- the only permitted exception is ``CrsysError``. A
  ``struct.error``, ``ValueError`` or ``IndexError`` escaping the library means a
  malformed input reached code that assumed it was well-formed.

Run a long campaign with::

    python tests/test_fuzz.py --iterations 200000 --seed 7
"""

from __future__ import annotations

import argparse
import random
import sys
import unittest

import _ctx  # noqa: F401

from crsys import (
    SUITE_AES256GCM,
    SUITE_CHACHA20POLY1305,
    KeyPair,
    PublicKey,
    decrypt_bytes,
    encrypt_bytes,
    inspect_container,
    kdf,
)
from crsys.errors import CrsysError

# Kept small so a campaign spends its time on mutations, not on key generation.
IN_SUITE_ITERATIONS = 2500
IN_SUITE_SEED = 20260802


# --------------------------------------------------------------------- corpus


class Sample:
    """One valid input plus everything needed to check the invariant."""

    def __init__(self, name, data, keypair, plaintext, armored=False):
        self.name = name
        self.data = data
        self.keypair = keypair
        self.plaintext = plaintext
        self.armored = armored


def build_corpus():
    """Valid containers across the shapes the format actually admits."""
    alice = KeyPair.generate(comment="alice")
    bob = KeyPair.generate(comment="bob")
    carol = KeyPair.generate(comment="carol")

    samples = []

    def add(name, plaintext, armored=False, **kwargs):
        kwargs.setdefault("recipients", [bob.public_key])
        blob = encrypt_bytes(plaintext, armored=armored, **kwargs)
        payload = blob.encode("utf-8") if isinstance(blob, str) else blob
        samples.append(Sample(name, payload, bob, plaintext, armored))

    add("empty", b"")
    add("tiny", b"x")
    add("one-chunk", b"A" * 500, chunk_size=1024)
    add("exact-chunk", b"B" * 1024, chunk_size=1024)
    add("multi-chunk", b"C" * 5000, chunk_size=1024)
    add("signed", b"signed payload" * 20, signer=alice, chunk_size=1024)
    add("signed-multi-chunk", b"D" * 4000, signer=alice, chunk_size=1024)
    add("aes-gcm", b"E" * 2000, suite=SUITE_AES256GCM, chunk_size=1024)
    add("chacha", b"F" * 2000, suite=SUITE_CHACHA20POLY1305, chunk_size=1024)
    add("hidden-recipients", b"G" * 300, hide_recipients=True, chunk_size=1024)
    add("three-recipients", b"H" * 900,
        recipients=[bob.public_key, alice.public_key, carol.public_key],
        chunk_size=1024)
    add("many-recipients", b"I" * 100,
        recipients=[bob.public_key] + [KeyPair.generate().public_key
                                       for _ in range(12)])
    add("armored", b"J" * 800, armored=True, chunk_size=1024)
    add("armored-signed", b"K" * 1500, armored=True, signer=alice, chunk_size=1024)
    return samples


def build_text_corpus():
    """Key files and public keys, for the text parsers.

    The encrypted key files matter most: their headers carry the KDF name and
    cost parameters, which is caller-controlled structured data reaching a
    parser. Both defects this fuzzer has found so far lived on that path.
    """
    key = KeyPair.generate(comment="fuzz target")
    corpus = [
        ("public-key", key.public_key.to_text().encode("utf-8")),
        ("public-compact", key.public_key.to_compact().encode("ascii")),
        ("private-plain", key.to_text(None).encode("utf-8")),
    ]

    original = kdf.default_params
    try:
        kdf.default_params = lambda: kdf.KdfParams(
            "scrypt", {"n": 1024, "r": 8, "p": 1}, b"0123456789abcdef")
        corpus.append(("private-scrypt", key.to_text(b"pw").encode("utf-8")))
        if kdf.ARGON2_AVAILABLE:
            kdf.default_params = lambda: kdf.KdfParams(
                "argon2id", {"t": 1, "m": 64, "p": 1}, b"0123456789abcdef")
            corpus.append(("private-argon2", key.to_text(b"pw").encode("utf-8")))
    finally:
        kdf.default_params = original

    return corpus


# ------------------------------------------------------------------ mutators


def m_flip_bits(rng, data):
    out = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        i = rng.randrange(len(out))
        out[i] ^= 1 << rng.randrange(8)
    return bytes(out)


def m_overwrite(rng, data):
    out = bytearray(data)
    start = rng.randrange(len(out))
    length = min(len(out) - start, rng.randint(1, 24))
    out[start:start + length] = bytes(rng.randrange(256) for _ in range(length))
    return bytes(out)


def m_truncate(rng, data):
    return data[:rng.randrange(len(data))]


def m_append(rng, data):
    return data + bytes(rng.randrange(256) for _ in range(rng.randint(1, 40)))


def m_delete_slice(rng, data):
    start = rng.randrange(len(data))
    length = min(len(data) - start, rng.randint(1, 32))
    return data[:start] + data[start + length:]


def m_duplicate_slice(rng, data):
    start = rng.randrange(len(data))
    length = min(len(data) - start, rng.randint(1, 64))
    chunk = data[start:start + length]
    at = rng.randrange(len(data))
    return data[:at] + chunk + data[at:]


def m_swap_slices(rng, data):
    if len(data) < 16:
        return m_flip_bits(rng, data)
    size = rng.randint(4, min(64, len(data) // 2))
    a = rng.randrange(0, len(data) - size)
    b = rng.randrange(0, len(data) - size)
    out = bytearray(data)
    out[a:a + size], out[b:b + size] = data[b:b + size], data[a:a + size]
    return bytes(out)


# Header-aware mutations: these aim straight at the fields a naive parser trusts.
_HEADER_FIELDS = {
    "version": (4, 1),
    "suite": (5, 1),
    "flags": (6, 1),
    "reserved": (7, 1),
    "chunk_size": (8, 4),
    "cek_commit": (12, 32),
    "n_recipients": (44, 2),
}

_INTERESTING = [0, 1, 2, 127, 128, 255, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF]


def m_header_field(rng, data):
    if len(data) < 46:
        return m_flip_bits(rng, data)
    name = rng.choice(list(_HEADER_FIELDS))
    offset, size = _HEADER_FIELDS[name]
    value = rng.choice(_INTERESTING) % (1 << (8 * size))
    out = bytearray(data)
    out[offset:offset + size] = value.to_bytes(size, "big")
    return bytes(out)


def m_length_prefix(rng, data):
    """Corrupt one of the uint32 chunk length prefixes."""
    positions = _chunk_offsets(data)
    if not positions:
        return m_flip_bits(rng, data)
    at = rng.choice(positions)
    value = rng.choice(_INTERESTING) % (1 << 32)
    out = bytearray(data)
    out[at:at + 4] = value.to_bytes(4, "big")
    return bytes(out)


def m_chunk_surgery(rng, data):
    """Drop, duplicate or reorder whole framed chunks."""
    positions = _chunk_offsets(data)
    if len(positions) < 2:
        return m_flip_bits(rng, data)
    header = data[:positions[0]]
    chunks = []
    for at in positions:
        size = int.from_bytes(data[at:at + 4], "big")
        chunks.append(data[at:at + 4 + size])
    action = rng.randrange(3)
    if action == 0:
        del chunks[rng.randrange(len(chunks))]
    elif action == 1:
        i = rng.randrange(len(chunks))
        chunks.insert(i, chunks[i])
    else:
        i, j = rng.randrange(len(chunks)), rng.randrange(len(chunks))
        chunks[i], chunks[j] = chunks[j], chunks[i]
    return header + b"".join(chunks)


def _chunk_offsets(data):
    """Offsets of each chunk's length prefix, best effort on valid framing."""
    if len(data) < 46 or data[:4] != b"CRSY":
        return []
    count = int.from_bytes(data[44:46], "big")
    at = 46 + count * 72
    offsets = []
    while at + 4 <= len(data):
        size = int.from_bytes(data[at:at + 4], "big")
        if size <= 0 or at + 4 + size > len(data):
            break
        offsets.append(at)
        at += 4 + size
    return offsets


BINARY_MUTATORS = [
    m_flip_bits, m_overwrite, m_truncate, m_append, m_delete_slice,
    m_duplicate_slice, m_swap_slices, m_header_field, m_length_prefix,
    m_chunk_surgery,
]

TEXT_MUTATORS = [
    m_flip_bits, m_overwrite, m_truncate, m_append, m_delete_slice,
    m_duplicate_slice, m_swap_slices,
]


# -------------------------------------------------------------------- engine


class Failure(Exception):
    pass


def _check_container(sample, mutated, iteration, mutator):
    where = "sample=%s mutator=%s iteration=%d" % (sample.name, mutator, iteration)

    try:
        out = decrypt_bytes(mutated, sample.keypair)
    except CrsysError:
        pass
    except Exception as exc:
        raise Failure(
            "%s: unexpected %s: %s" % (where, type(exc).__name__, exc)) from exc
    else:
        if mutated == sample.data:
            if out != sample.plaintext:
                raise Failure("%s: unmodified input decrypted incorrectly" % where)
        elif sample.armored:
            # Whitespace and surrounding text are outside the authenticated data,
            # so success is legitimate -- but the plaintext must be untouched.
            if out != sample.plaintext:
                raise Failure("%s: armored mutation changed the plaintext" % where)
        else:
            raise Failure("%s: MALLEABLE -- modified container still decrypted" % where)

    # Header parsing must be just as strict when no key is involved.
    try:
        inspect_container(_reader(mutated))
    except CrsysError:
        pass
    except Exception as exc:
        raise Failure(
            "%s: inspect raised %s: %s" % (where, type(exc).__name__, exc)) from exc


def _check_text(name, mutated, iteration, mutator):
    where = "sample=%s mutator=%s iteration=%d" % (name, mutator, iteration)
    try:
        text = mutated.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - decode with replace cannot fail
        raise Failure(
            "%s: decode raised %s" % (where, type(exc).__name__)) from exc

    for parse in (PublicKey.parse, lambda t: KeyPair.from_text(t, b"pw"),
                  lambda t: KeyPair.from_text(t, None)):
        try:
            parse(text)
        except CrsysError:
            pass
        except Exception as exc:
            raise Failure(
                "%s: %s: %s" % (where, type(exc).__name__, exc)) from exc


def _reader(data):
    import io

    return io.BytesIO(data)


def run_campaign(iterations, seed, verbose=False):
    """Returns (checks_run, mutations_that_changed_the_input).

    The KDF memory ceiling is lowered for the duration: a mutation is free to
    rewrite the cost parameters of an encrypted key file, and honouring them
    would have the fuzzer spend its time allocating memory rather than exploring
    the parser. The parsing path under test is identical either way.
    """
    rng = random.Random(seed)
    corpus = build_corpus()
    text_corpus = build_text_corpus()
    changed = 0

    real_ceiling = kdf.MAX_MEMORY_BYTES
    kdf.MAX_MEMORY_BYTES = 4 << 20
    try:
        changed = _campaign_loop(rng, corpus, text_corpus, iterations, verbose)
    finally:
        kdf.MAX_MEMORY_BYTES = real_ceiling
    return iterations, changed


def _campaign_loop(rng, corpus, text_corpus, iterations, verbose):
    changed = 0
    for iteration in range(iterations):
        if iteration % 5 == 4:
            name, data = rng.choice(text_corpus)
            mutator = rng.choice(TEXT_MUTATORS)
            mutated = mutator(rng, data)
            if mutated != data:
                changed += 1
            _check_text(name, mutated, iteration, mutator.__name__)
            continue

        sample = rng.choice(corpus)
        mutator = rng.choice(BINARY_MUTATORS)
        mutated = mutator(rng, sample.data)
        if not mutated:
            mutated = b"\x00"
        if mutated != sample.data:
            changed += 1
        _check_container(sample, mutated, iteration, mutator.__name__)

        if verbose and iteration % 10000 == 0 and iteration:
            print("  %d iterations..." % iteration, flush=True)

    return changed


# ---------------------------------------------------------------- unit test


class TestFuzz(unittest.TestCase):
    """A fixed-seed campaign, so the suite exercises the parsers on every run."""

    def test_mutation_campaign(self):
        try:
            total, changed = run_campaign(IN_SUITE_ITERATIONS, IN_SUITE_SEED)
        except Failure as exc:
            self.fail("%s\n(replay: python tests/test_fuzz.py --seed %d)"
                      % (exc, IN_SUITE_SEED))
        self.assertEqual(total, IN_SUITE_ITERATIONS)
        # A campaign where nothing actually changed would pass vacuously.
        self.assertGreater(changed, IN_SUITE_ITERATIONS * 0.9)

    def test_corpus_is_valid_before_mutation(self):
        for sample in build_corpus():
            with self.subTest(sample=sample.name):
                self.assertEqual(decrypt_bytes(sample.data, sample.keypair),
                                 sample.plaintext)


# --------------------------------------------------------------------- main


def main(argv=None):
    parser = argparse.ArgumentParser(description="CRSYS mutation fuzzer")
    parser.add_argument("-n", "--iterations", type=int, default=50000)
    parser.add_argument("-s", "--seed", type=int, default=IN_SUITE_SEED)
    args = parser.parse_args(argv)

    print("CRSYS fuzzer -- %d iterations, seed %d" % (args.iterations, args.seed))
    try:
        total, changed = run_campaign(args.iterations, args.seed, verbose=True)
    except Failure as exc:
        print("\nFAILURE: %s" % exc)
        return 1
    print("OK -- %d iterations, %d of them changed the input" % (total, changed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
