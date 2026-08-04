"""CRSYS command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import List, Optional

from . import __version__
from .armor import ArmorWriter
from .container import DEFAULT_CHUNK_SIZE
from .core import (
    decrypt_file,
    decrypt_stream,
    encrypt_file,
    encrypt_stream,
    inspect_container,
    sign_detached_stream,
    verify_detached_stream,
)
from .errors import CrsysError, PassphraseError, SignatureError
from .keys import KeyPair, PublicKey
from .suite import SUITE_BY_NAME, suite_name

# Suppressed on the next line: the name of an environment variable, not a passphrase.
ENV_PASSPHRASE = "CRSYS_PASSPHRASE"  # noqa: S105

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_CRYPTO = 2
EXIT_SIGNATURE = 3


# ------------------------------------------------------------------ passphrase


def _read_passphrase(args, confirm: bool = False) -> Optional[bytes]:
    """Passphrase from a file, an environment variable, or the terminal."""
    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file, "rb") as fh:
            return fh.read().split(b"\n")[0].strip() or None
    env = os.environ.get(ENV_PASSPHRASE)
    if env:
        return env.encode("utf-8")
    if not sys.stdin.isatty():
        raise CrsysError(
            "a passphrase is required but the terminal is not interactive: use "
            "--passphrase-file or the %s environment variable" % ENV_PASSPHRASE
        )
    first = getpass.getpass("Passphrase: ")
    if not confirm:
        return first.encode("utf-8") or None
    second = getpass.getpass("Repeat the passphrase: ")
    if first != second:
        raise CrsysError("the two passphrases do not match")
    return first.encode("utf-8") or None


def _load_private(path: str, args) -> KeyPair:
    if not KeyPair.is_encrypted(path):
        return KeyPair.load(path)
    return KeyPair.load(path, _read_passphrase(args))


# --------------------------------------------------------------------- file I/O


def _open_in(path: str):
    if path == "-":
        return sys.stdin.buffer, False
    return open(path, "rb"), True


def _open_out(path: str):
    if path == "-":
        return sys.stdout.buffer, False
    return open(path, "wb"), True


def _is_stream(path: str) -> bool:
    return path == "-"


def _refuse_overwrite(path: str, force: bool) -> None:
    if path != "-" and os.path.exists(path) and not force:
        raise CrsysError("%s already exists (use --force to overwrite)" % path)


# -------------------------------------------------------------------- commands


def cmd_keygen(args) -> int:
    base = args.output
    for suffix in (".key", ".pub"):
        base = base.removesuffix(suffix)
    priv_path, pub_path = base + ".key", base + ".pub"
    _refuse_overwrite(priv_path, args.force)
    _refuse_overwrite(pub_path, args.force)

    passphrase = None if args.no_passphrase else _read_passphrase(args, confirm=True)
    if passphrase is None and not args.no_passphrase:
        raise CrsysError("empty passphrase: pass --no-passphrase if that is intended")

    keypair = KeyPair.generate(comment=args.comment or "")
    restricted = keypair.save(priv_path, passphrase)
    keypair.public_key.save(pub_path)

    print("Private key : %s%s" % (priv_path, "" if passphrase else "  (UNENCRYPTED)"))
    print("Public key  : %s" % pub_path)
    print("Fingerprint : %s" % keypair.fingerprint_hex)
    print("Compact form: %s" % keypair.public_key.to_compact())
    if passphrase is None:
        print(
            "\nWARNING: the private key is stored in the clear. Anyone who can read\n"
            "%s can decrypt all of your messages." % priv_path,
            file=sys.stderr,
        )
    if not restricted:
        print(
            "\nWARNING: could not restrict %s to your account. The key is saved and\n"
            "usable, but its permissions are whatever the folder allows." % priv_path,
            file=sys.stderr,
        )
    return EXIT_OK


def cmd_pubkey(args) -> int:
    keypair = _load_private(args.key, args)
    pub = keypair.public_key
    if args.compact:
        print(pub.to_compact())
    else:
        sys.stdout.write(pub.to_text())
    return EXIT_OK


def cmd_fingerprint(args) -> int:
    for path in args.keys:
        try:
            key = PublicKey.parse(path)
        except CrsysError:
            key = _load_private(path, args).public_key
        label = key.comment or os.path.basename(path)
        print("%s  %s" % (key.fingerprint_hex, label))
    return EXIT_OK


def cmd_encrypt(args) -> int:
    recipients: List[PublicKey] = [PublicKey.parse(value) for value in args.recipient]
    signer = _load_private(args.sign, args) if args.sign else None
    if args.self_recipient:
        if signer is None:
            raise CrsysError("--self requires --sign")
        recipients.append(signer.public_key)
    suite = SUITE_BY_NAME.get(args.suite.lower())
    if suite is None:
        raise CrsysError("unknown suite: %s" % args.suite)
    _refuse_overwrite(args.output, args.force)

    if _is_stream(args.input) or _is_stream(args.output):
        fin, close_in = _open_in(args.input)
        fout, close_out = _open_out(args.output)
        wrapper = ArmorWriter(fout) if args.armor else fout
        try:
            result = encrypt_stream(
                fin, wrapper, recipients, signer, suite, args.chunk_size,
                args.hide_recipients
            )
            if args.armor:
                wrapper.close()
        finally:
            if close_in:
                fin.close()
            if close_out:
                fout.close()
    else:
        result = encrypt_file(
            args.input,
            args.output,
            recipients,
            signer,
            suite,
            args.chunk_size,
            args.hide_recipients,
            args.armor,
        )

    if not args.quiet:
        print(
            "Encrypted %d bytes -> %d bytes  [%s]"
            % (result.plaintext_bytes, result.ciphertext_bytes, suite_name(suite)),
            file=sys.stderr,
        )
        for fpr in result.recipients:
            print("  recipient: %s" % fpr, file=sys.stderr)
        if result.signed_by:
            print("  signed by: %s" % result.signed_by, file=sys.stderr)
    return EXIT_OK


def cmd_decrypt(args) -> int:
    keypair = _load_private(args.key, args)
    expected = PublicKey.parse(args.require_signer) if args.require_signer else None
    _refuse_overwrite(args.output, args.force)

    if _is_stream(args.input) or _is_stream(args.output):
        fin, close_in = _open_in(args.input)
        fout, close_out = _open_out(args.output)
        try:
            result = decrypt_stream(fin, fout, keypair, expected)
        finally:
            if close_in:
                fin.close()
            if close_out:
                fout.close()
    else:
        result = decrypt_file(args.input, args.output, keypair, expected)

    if not args.quiet:
        print(
            "Decrypted %d bytes  [%s]"
            % (result.plaintext_bytes, suite_name(result.suite)),
            file=sys.stderr,
        )
        if result.signer:
            print("  valid signature from: %s" % result.signer.fingerprint_hex,
                  file=sys.stderr)
        else:
            print("  message is unsigned (sender not authenticated)", file=sys.stderr)
    return EXIT_OK


def cmd_inspect(args) -> int:
    fin, close_in = _open_in(args.input)
    try:
        info = inspect_container(fin)
    finally:
        if close_in:
            fin.close()
    print("version     : %d" % info["version"])
    print("suite       : %s" % info["suite"])
    print("signed      : %s" % ("yes" if info["signed"] else "no"))
    print("chunk_size  : %d bytes" % info["chunk_size"])
    print("CEK commit  : %s" % info["cek_commit"])
    print("recipients  : %d" % len(info["recipients"]))
    for fpr in info["recipients"]:
        print("  - %s" % fpr)
    return EXIT_OK


def cmd_sign(args) -> int:
    keypair = _load_private(args.key, args)
    fin, close_in = _open_in(args.input)
    try:
        text = sign_detached_stream(keypair, fin)
    finally:
        if close_in:
            fin.close()
    if args.output == "-":
        sys.stdout.write(text)
    else:
        _refuse_overwrite(args.output, args.force)
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return EXIT_OK


def cmd_verify(args) -> int:
    with open(args.signature, "r", encoding="utf-8") as fh:
        signature_text = fh.read()
    expected = PublicKey.parse(args.require_signer) if args.require_signer else None
    fin, close_in = _open_in(args.input)
    try:
        signer = verify_detached_stream(fin, signature_text, expected)
    finally:
        if close_in:
            fin.close()
    print("Signature VALID from %s" % signer.fingerprint_hex)
    return EXIT_OK


def cmd_passwd(args) -> int:
    keypair = _load_private(args.key, args)  # current passphrase
    if args.no_passphrase:
        new: Optional[bytes] = None
    elif args.new_passphrase_file:
        with open(args.new_passphrase_file, "rb") as fh:
            new = fh.read().split(b"\n")[0].strip() or None
    else:
        if not sys.stdin.isatty():
            raise CrsysError(
                "non-interactive terminal: use --new-passphrase-file or --no-passphrase"
            )
        first = getpass.getpass("New passphrase: ")
        second = getpass.getpass("Repeat the new passphrase: ")
        if first != second:
            raise CrsysError("the two passphrases do not match")
        new = first.encode("utf-8") or None
    if new is None and not args.no_passphrase:
        raise CrsysError("empty passphrase: pass --no-passphrase if that is intended")
    keypair.save(args.key, new)
    print("Key %s rewritten%s." % (keypair.fingerprint_hex,
                                   "" if new else " WITHOUT a passphrase"))
    return EXIT_OK


# ---------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crsys",
        description="Hybrid public-key encryption (X25519 + Ed25519 + AEAD).",
    )
    parser.add_argument("--version", action="version", version="crsys %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_pass_opts(p):
        p.add_argument(
            "--passphrase-file",
            metavar="FILE",
            help="read the passphrase from the first line of FILE (for automation)",
        )

    # keygen
    p = sub.add_parser("keygen", help="generate a new key pair")
    p.add_argument("-o", "--output", required=True, metavar="NAME",
                   help="prefix: creates NAME.key and NAME.pub")
    p.add_argument("-c", "--comment", help="free-form label stored in the key files")
    p.add_argument("--no-passphrase", action="store_true",
                   help="store the private key unencrypted (not recommended)")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    add_pass_opts(p)
    p.set_defaults(func=cmd_keygen)

    # pubkey
    p = sub.add_parser("pubkey", help="print the public key of a private key")
    p.add_argument("-k", "--key", required=True, metavar="FILE")
    p.add_argument("--compact", action="store_true", help="one-line crsys1... form")
    add_pass_opts(p)
    p.set_defaults(func=cmd_pubkey)

    # fingerprint
    p = sub.add_parser("fingerprint", help="show the fingerprint of one or more keys")
    p.add_argument("keys", nargs="+", metavar="KEY")
    add_pass_opts(p)
    p.set_defaults(func=cmd_fingerprint)

    # encrypt
    p = sub.add_parser("encrypt", help="encrypt for one or more recipients")
    p.add_argument("-r", "--recipient", action="append", required=True, metavar="KEY",
                   help=".pub file, armored block or compact form; repeatable")
    p.add_argument("-i", "--input", default="-", metavar="FILE", help="'-' for stdin")
    p.add_argument("-o", "--output", default="-", metavar="FILE", help="'-' for stdout")
    p.add_argument("-s", "--sign", metavar="FILE", help="private key to sign with")
    p.add_argument("--self", dest="self_recipient", action="store_true",
                   help="add the sender as a recipient (to re-read what you sent)")
    p.add_argument("--armor", action="store_true",
                   help="ASCII output instead of binary")
    p.add_argument("--hide-recipients", action="store_true",
                   help="zero out the fingerprints in the header")
    p.add_argument("--suite", default="chacha20poly1305",
                   choices=sorted(SUITE_BY_NAME), help="payload cipher")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, metavar="N")
    p.add_argument("--force", action="store_true", help="overwrite the output file")
    p.add_argument("-q", "--quiet", action="store_true")
    add_pass_opts(p)
    p.set_defaults(func=cmd_encrypt)

    # decrypt
    p = sub.add_parser("decrypt", help="decrypt a container")
    p.add_argument("-k", "--key", required=True, metavar="FILE", help="private key")
    p.add_argument("-i", "--input", default="-", metavar="FILE")
    p.add_argument("-o", "--output", default="-", metavar="FILE")
    p.add_argument("--require-signer", metavar="KEY",
                   help="fail unless the message is signed by this key")
    p.add_argument("--force", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    add_pass_opts(p)
    p.set_defaults(func=cmd_decrypt)

    # inspect
    p = sub.add_parser("inspect", help="show a container's public metadata")
    p.add_argument("-i", "--input", default="-", metavar="FILE")
    p.set_defaults(func=cmd_inspect)

    # sign
    p = sub.add_parser("sign", help="detached signature (the file stays in the clear)")
    p.add_argument("-k", "--key", required=True, metavar="FILE")
    p.add_argument("-i", "--input", default="-", metavar="FILE")
    p.add_argument("-o", "--output", default="-", metavar="FILE")
    p.add_argument("--force", action="store_true")
    add_pass_opts(p)
    p.set_defaults(func=cmd_sign)

    # verify
    p = sub.add_parser("verify", help="verify a detached signature")
    p.add_argument("-i", "--input", default="-", metavar="FILE")
    p.add_argument("-S", "--signature", required=True, metavar="FILE")
    p.add_argument("--require-signer", metavar="KEY")
    p.set_defaults(func=cmd_verify)

    # passwd
    p = sub.add_parser("passwd", help="change a private key's passphrase")
    p.add_argument("-k", "--key", required=True, metavar="FILE")
    p.add_argument("--no-passphrase", action="store_true",
                   help="remove the protection (not recommended)")
    p.add_argument("--new-passphrase-file", metavar="FILE",
                   help="read the new passphrase from the first line of FILE")
    add_pass_opts(p)
    p.set_defaults(func=cmd_passwd)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SignatureError as exc:
        print("crsys: signature: %s" % exc, file=sys.stderr)
        return EXIT_SIGNATURE
    except (PassphraseError, CrsysError) as exc:
        print("crsys: %s" % exc, file=sys.stderr)
        return EXIT_CRYPTO
    except FileNotFoundError as exc:
        print("crsys: file not found: %s" % exc.filename, file=sys.stderr)
        return EXIT_USAGE
    except BrokenPipeError:  # pragma: no cover
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover
        print("\ncrsys: interrupted", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
