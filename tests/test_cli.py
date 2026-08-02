"""End-to-end tests for the command-line interface."""

from __future__ import annotations

import contextlib
import io
import os
import secrets
import sys
import tempfile
import unittest

from _ctx import CheapKdf

from crsys.cli import ENV_PASSPHRASE, EXIT_CRYPTO, EXIT_OK, EXIT_SIGNATURE, main

PASSPHRASE = "test-passphrase"


def run(*argv):
    """Invoke the CLI, capturing stdout and stderr."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class _FakeStdStream:
    """Stands in for sys.stdin / sys.stdout, which the CLI reaches through .buffer."""

    def __init__(self, data: bytes = b"") -> None:
        self.buffer = io.BytesIO(data)
        self.text = io.StringIO()

    def write(self, value):       # print() goes here, not to .buffer
        return self.text.write(value)

    def flush(self):
        pass

    def isatty(self):
        return False


@contextlib.contextmanager
def piped(stdin: bytes = b""):
    """Run the CLI with real byte pipes, the way a shell would."""
    saved_in, saved_out, saved_err = sys.stdin, sys.stdout, sys.stderr
    fin, fout, ferr = _FakeStdStream(stdin), _FakeStdStream(), _FakeStdStream()
    sys.stdin, sys.stdout, sys.stderr = fin, fout, ferr
    try:
        yield fin, fout
    finally:
        sys.stdin, sys.stdout, sys.stderr = saved_in, saved_out, saved_err


class TestCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self._old_env = os.environ.get(ENV_PASSPHRASE)
        os.environ[ENV_PASSPHRASE] = PASSPHRASE
        self._kdf = CheapKdf()
        self._kdf.__enter__()

        self.alice = self.p("alice")
        self.bob = self.p("bob")
        self.assertEqual(run("keygen", "-o", self.alice, "-c", "alice")[0], EXIT_OK)
        self.assertEqual(run("keygen", "-o", self.bob, "-c", "bob")[0], EXIT_OK)

        self.plain = self.p("document.txt")
        self.data = ("test line\n" * 500).encode() + secrets.token_bytes(1000)
        with open(self.plain, "wb") as fh:
            fh.write(self.data)

    def tearDown(self):
        self._kdf.__exit__(None, None, None)
        if self._old_env is None:
            os.environ.pop(ENV_PASSPHRASE, None)
        else:
            os.environ[ENV_PASSPHRASE] = self._old_env
        self._tmp.cleanup()

    def p(self, name):
        return os.path.join(self.dir, name)

    # -------------------------------------------------------------------- keys

    def test_keygen_creates_both_files(self):
        self.assertTrue(os.path.exists(self.alice + ".key"))
        self.assertTrue(os.path.exists(self.alice + ".pub"))
        with open(self.alice + ".key", encoding="utf-8") as fh:
            self.assertIn("cipher: chacha20poly1305", fh.read())

    def test_keygen_does_not_overwrite(self):
        code, _, err = run("keygen", "-o", self.alice)
        self.assertEqual(code, EXIT_CRYPTO)
        self.assertIn("already exists", err)
        self.assertEqual(run("keygen", "-o", self.alice, "--force")[0], EXIT_OK)

    def test_pubkey_and_fingerprint(self):
        code, out, _ = run("pubkey", "-k", self.alice + ".key", "--compact")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(out.strip().startswith("crsys1"))

        code, out2, _ = run("fingerprint", self.alice + ".pub")
        self.assertEqual(code, EXIT_OK)
        self.assertRegex(out2, r"[0-9a-f]{4}(-[0-9a-f]{4}){3}")

    def test_wrong_passphrase(self):
        os.environ[ENV_PASSPHRASE] = "wrong"
        code, _, err = run("pubkey", "-k", self.alice + ".key")
        self.assertEqual(code, EXIT_CRYPTO)
        self.assertIn("passphrase", err.lower())

    def test_passwd_changes_the_passphrase(self):
        new = self.p("new.txt")
        with open(new, "w", encoding="utf-8") as fh:
            fh.write("another-passphrase\n")
        self.assertEqual(
            run("passwd", "-k", self.alice + ".key", "--new-passphrase-file", new)[0],
            EXIT_OK,
        )
        self.assertEqual(run("pubkey", "-k", self.alice + ".key")[0], EXIT_CRYPTO)
        os.environ[ENV_PASSPHRASE] = "another-passphrase"
        self.assertEqual(run("pubkey", "-k", self.alice + ".key")[0], EXIT_OK)

    # -------------------------------------------------------------- encryption

    def test_full_signed_flow(self):
        enc, dec = self.p("doc.crsys"), self.p("doc.out")
        code, _, err = run(
            "encrypt", "-r", self.bob + ".pub", "-s", self.alice + ".key",
            "-i", self.plain, "-o", enc,
        )
        self.assertEqual(code, EXIT_OK, err)
        self.assertTrue(os.path.exists(enc))

        code, _, err = run(
            "decrypt", "-k", self.bob + ".key", "-i", enc, "-o", dec,
            "--require-signer", self.alice + ".pub",
        )
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("valid signature", err)
        with open(dec, "rb") as fh:
            self.assertEqual(fh.read(), self.data)

    def test_wrong_recipient(self):
        enc = self.p("doc.crsys")
        run("encrypt", "-r", self.bob + ".pub", "-i", self.plain, "-o", enc)
        code, _, err = run(
            "decrypt", "-k", self.alice + ".key", "-i", enc, "-o", self.p("x")
        )
        self.assertEqual(code, EXIT_CRYPTO)
        self.assertIn("not for you", err)

    def test_signer_mismatch(self):
        enc = self.p("doc.crsys")
        run("encrypt", "-r", self.bob + ".pub", "-s", self.bob + ".key",
            "-i", self.plain, "-o", enc)
        code, _, err = run(
            "decrypt", "-k", self.bob + ".key", "-i", enc, "-o", self.p("x"),
            "--require-signer", self.alice + ".pub",
        )
        self.assertEqual(code, EXIT_SIGNATURE)
        self.assertIn("expected", err)

    def test_armor(self):
        enc, dec = self.p("doc.asc"), self.p("doc.out")
        run("encrypt", "-r", self.bob + ".pub", "-i", self.plain, "-o", enc, "--armor")
        with open(enc, encoding="ascii") as fh:
            text = fh.read()
        self.assertTrue(text.startswith("-----BEGIN CRSYS MESSAGE-----"))
        self.assertEqual(
            run("decrypt", "-k", self.bob + ".key", "-i", enc, "-o", dec)[0],
            EXIT_OK,
        )
        with open(dec, "rb") as fh:
            self.assertEqual(fh.read(), self.data)

    def test_multi_recipient_and_self(self):
        enc = self.p("doc.crsys")
        code, _, err = run(
            "encrypt", "-r", self.bob + ".pub", "-s", self.alice + ".key", "--self",
            "-i", self.plain, "-o", enc,
        )
        self.assertEqual(code, EXIT_OK, err)
        for key in (self.alice, self.bob):
            out = self.p("out-" + os.path.basename(key))
            self.assertEqual(
                run("decrypt", "-k", key + ".key", "-i", enc, "-o", out)[0],
                EXIT_OK,
            )

    def test_recipient_in_compact_form(self):
        _, compact, _ = run("pubkey", "-k", self.bob + ".key", "--compact")
        enc, dec = self.p("doc.crsys"), self.p("doc.out")
        code, _, err = run("encrypt", "-r", compact.strip(), "-i", self.plain, "-o", enc)
        self.assertEqual(code, EXIT_OK, err)
        self.assertEqual(
            run("decrypt", "-k", self.bob + ".key", "-i", enc, "-o", dec)[0],
            EXIT_OK,
        )

    def test_aes_suite(self):
        enc, dec = self.p("doc.crsys"), self.p("doc.out")
        run("encrypt", "-r", self.bob + ".pub", "-i", self.plain, "-o", enc,
            "--suite", "aes256gcm")
        code, out, _ = run("inspect", "-i", enc)
        self.assertIn("aes256gcm", out)
        self.assertEqual(
            run("decrypt", "-k", self.bob + ".key", "-i", enc, "-o", dec)[0],
            EXIT_OK,
        )

    def test_inspect(self):
        enc = self.p("doc.crsys")
        run("encrypt", "-r", self.bob + ".pub", "-s", self.alice + ".key",
            "-i", self.plain, "-o", enc)
        code, out, _ = run("inspect", "-i", enc)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("signed      : yes", out)
        self.assertIn("recipients  : 1", out)

    def test_hide_recipients(self):
        enc = self.p("doc.crsys")
        run("encrypt", "-r", self.bob + ".pub", "-i", self.plain, "-o", enc,
            "--hide-recipients")
        _, out, _ = run("inspect", "-i", enc)
        self.assertIn("anonymous", out)
        self.assertEqual(
            run("decrypt", "-k", self.bob + ".key", "-i", enc, "-o", self.p("o"))[0],
            EXIT_OK,
        )

    def test_tampered_file(self):
        enc = self.p("doc.crsys")
        run("encrypt", "-r", self.bob + ".pub", "-i", self.plain, "-o", enc)
        with open(enc, "r+b") as fh:
            fh.seek(200)
            fh.write(b"\x00")
        code, _, err = run("decrypt", "-k", self.bob + ".key", "-i", enc,
                           "-o", self.p("x"))
        self.assertEqual(code, EXIT_CRYPTO)
        self.assertFalse(os.path.exists(self.p("x")))

    # ------------------------------------------------------------ pipe mode

    def test_stdin_to_stdout(self):
        """The '-' paths are how the tool composes with other commands."""
        payload = b"piped secret\n" * 50
        with piped(payload) as (_fin, fout):
            code = main(["encrypt", "-r", self.bob + ".pub", "-i", "-", "-o", "-",
                         "--quiet"])
            sealed = fout.buffer.getvalue()
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(sealed.startswith(b"CRSY"))

        with piped(sealed) as (_fin, fout):
            code = main(["decrypt", "-k", self.bob + ".key", "-i", "-", "-o", "-",
                         "--quiet"])
            recovered = fout.buffer.getvalue()
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(recovered, payload)

    def test_stdin_to_stdout_armored_and_signed(self):
        payload = b"armored through a pipe"
        with piped(payload) as (_fin, fout):
            code = main(["encrypt", "-r", self.bob + ".pub", "-s", self.alice + ".key",
                         "-i", "-", "-o", "-", "--armor", "--quiet"])
            sealed = fout.buffer.getvalue()
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(sealed.startswith(b"-----BEGIN CRSYS MESSAGE-----"))
        self.assertTrue(sealed.rstrip().endswith(b"-----END CRSYS MESSAGE-----"))

        with piped(sealed) as (_fin, fout):
            code = main(["decrypt", "-k", self.bob + ".key", "-i", "-", "-o", "-",
                         "--require-signer", self.alice + ".pub", "--quiet"])
            recovered = fout.buffer.getvalue()
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(recovered, payload)

    def test_inspect_from_stdin(self):
        enc = self.p("doc.crsys")
        run("encrypt", "-r", self.bob + ".pub", "-i", self.plain, "-o", enc)
        with open(enc, "rb") as fh:
            sealed = fh.read()
        with piped(sealed) as (_fin, fout):
            code = main(["inspect", "-i", "-"])
            printed = fout.text.getvalue()
        self.assertEqual(code, EXIT_OK)
        self.assertIn("recipients  : 1", printed)

    # -------------------------------------------------------- passphrase input

    def test_passphrase_file(self):
        """Automation path: no environment variable, no terminal."""
        pw_file = self.p("pw.txt")
        with open(pw_file, "w", encoding="utf-8") as fh:
            fh.write(PASSPHRASE + "\nignored second line\n")
        del os.environ[ENV_PASSPHRASE]
        try:
            code, out, err = run("pubkey", "-k", self.alice + ".key",
                                 "--compact", "--passphrase-file", pw_file)
            self.assertEqual(code, EXIT_OK, err)
            self.assertTrue(out.strip().startswith("crsys1"))
        finally:
            os.environ[ENV_PASSPHRASE] = PASSPHRASE

    def test_no_passphrase_source_and_no_terminal(self):
        """Without a tty and without a source, the message must say what to do."""
        del os.environ[ENV_PASSPHRASE]
        try:
            with piped() as (_fin, _fout):
                code = main(["pubkey", "-k", self.alice + ".key"])
            self.assertEqual(code, EXIT_CRYPTO)
        finally:
            os.environ[ENV_PASSPHRASE] = PASSPHRASE

    def test_unencrypted_key_needs_no_passphrase(self):
        plain_key = self.p("plain")
        self.assertEqual(
            run("keygen", "-o", plain_key, "--no-passphrase")[0], EXIT_OK)
        del os.environ[ENV_PASSPHRASE]
        try:
            code, out, _ = run("pubkey", "-k", plain_key + ".key", "--compact")
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(out.strip().startswith("crsys1"))
        finally:
            os.environ[ENV_PASSPHRASE] = PASSPHRASE

    # ------------------------------------------------------ detached signatures

    def test_sign_verify(self):
        sig = self.p("doc.sig")
        self.assertEqual(
            run("sign", "-k", self.alice + ".key", "-i", self.plain, "-o", sig)[0],
            EXIT_OK,
        )
        code, out, _ = run("verify", "-i", self.plain, "-S", sig,
                           "--require-signer", self.alice + ".pub")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("VALID", out)

        with open(self.plain, "ab") as fh:
            fh.write(b"modification")
        self.assertEqual(run("verify", "-i", self.plain, "-S", sig)[0],
                         EXIT_SIGNATURE)


if __name__ == "__main__":
    unittest.main()
