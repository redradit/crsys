"""Sign tab: detached signatures, leaving the file in the clear."""

from __future__ import annotations

import os
from typing import List

import customtkinter as ctk

from crsys import sign_detached_stream, verify_detached_stream

from . import theme
from .keyring import Identity
from .widgets import ALL_FILES, Banner, FilePicker, IdentityChooser, Panel, TextPanel, hint, section

SIG_FILES = [("CRSYS signatures", "*.sig"), ("All files", "*.*")]


class SignPanel(Panel):
    def __init__(self, master, app) -> None:
        super().__init__(master, app)
        self._identities: List[Identity] = []

        self.grid_columnconfigure(0, weight=1, uniform="col")
        self.grid_columnconfigure(1, weight=1, uniform="col")
        self.grid_rowconfigure(0, weight=1)

        self._build_sign()
        self._build_verify()

    # -------------------------------------------------------------------- sign

    def _build_sign(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, theme.PAD_S))
        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        ctk.CTkLabel(inner, text="Sign a file", anchor="w",
                     font=ctk.CTkFont(size=theme.TITLE_SIZE, weight="bold")
                     ).pack(fill="x")
        hint(inner, "The file is neither encrypted nor modified: a separate "
                    "signature is produced that anyone can verify with your "
                    "public key.")

        section(inner, "File to sign")
        self._sign_input = FilePicker(inner, mode="open", title="File to sign",
                                      filetypes=ALL_FILES,
                                      on_change=self._suggest_signature_path)
        self._sign_input.pack(fill="x")

        section(inner, "Sign with")
        self._signer = IdentityChooser(inner)
        self._signer.pack(fill="x")

        section(inner, "Save the signature to")
        self._sign_output = FilePicker(inner, mode="save", title="Save the signature",
                                       filetypes=SIG_FILES, default_extension=".sig")
        self._sign_output.pack(fill="x")

        self._sign_banner = Banner(inner)

        self._sign_text = TextPanel(inner, "Signature produced", height=110,
                                    readonly=True)
        self._sign_text.pack(fill="both", expand=True, pady=(theme.PAD, 0))

        ctk.CTkButton(inner, text="Sign", height=36,
                      font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold"),
                      command=self._sign).pack(fill="x", pady=(theme.PAD, 0))

    # ------------------------------------------------------------------ verify

    def _build_verify(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.grid(row=0, column=1, sticky="nsew", padx=(theme.PAD_S, 0))
        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        ctk.CTkLabel(inner, text="Verify a signature", anchor="w",
                     font=ctk.CTkFont(size=theme.TITLE_SIZE, weight="bold")
                     ).pack(fill="x")
        hint(inner, "Confirms that the file was not touched after signing and that "
                    "it came from the private key shown.")

        section(inner, "Original file")
        self._verify_input = FilePicker(inner, mode="open", title="File to verify",
                                        filetypes=ALL_FILES)
        self._verify_input.pack(fill="x")

        section(inner, "Signature file")
        self._verify_sig = FilePicker(inner, mode="open", title=".sig file",
                                      filetypes=SIG_FILES)
        self._verify_sig.pack(fill="x")

        section(inner, "Expected sender")
        self._expected = IdentityChooser(inner, allow_none=True)
        self._expected.pack(fill="x")

        self._verify_banner = Banner(inner)

        self._verify_text = TextPanel(inner, "…or paste the signature here",
                                      height=110)
        self._verify_text.pack(fill="both", expand=True, pady=(theme.PAD, 0))

        ctk.CTkButton(inner, text="Verify", height=36,
                      font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold"),
                      command=self._verify).pack(fill="x", pady=(theme.PAD, 0))

    # ------------------------------------------------------------------ state

    def on_identities_changed(self, identities: List[Identity]) -> None:
        self._identities = identities
        self._signer.set_identities([i for i in identities
                                     if i.has_private and not i.error])
        self._expected.set_identities([i for i in identities if i.public_key])

    def _suggest_signature_path(self) -> None:
        source = self._sign_input.get()
        if source and not self._sign_output.get():
            self._sign_output.set(source + ".sig")

    # ---------------------------------------------------------------- actions

    def _sign(self) -> None:
        self._sign_banner.clear()
        source = self._sign_input.get()
        if not source or not os.path.isfile(source):
            self._sign_banner.show("Choose a file to sign.", "error")
            return
        name = self._signer.selected_name()
        if not name:
            self._sign_banner.show("A private key is required in the keyring.", "error")
            return
        destination = self._sign_output.get()

        proceed, passphrase = self.app.ask_unlock(name)
        if not proceed:
            return

        def job(_report):
            keypair = self.app.keypair(name, passphrase)
            with open(source, "rb") as fh:
                signature = sign_detached_stream(keypair, fh)
            if destination:
                with open(destination, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(signature)
            return signature

        def done(signature):
            self._sign_text.set(signature)
            self._sign_banner.show(
                "Signed with \"%s\".%s" % (name, "\nSaved to %s" % destination
                                           if destination else ""), "ok")
            self.app.status.message("Signature created.", "ok")

        self.app.status.message("Signing…")
        self.app.run(job, done, "Signing failed",
                     on_fail=lambda message: self._sign_banner.show(message, "error"))

    def _verify(self) -> None:
        self._verify_banner.clear()
        source = self._verify_input.get()
        if not source or not os.path.isfile(source):
            self._verify_banner.show("Choose the file to verify.", "error")
            return

        signature = self._verify_text.get()
        if not signature:
            path = self._verify_sig.get()
            if not path or not os.path.isfile(path):
                self._verify_banner.show(
                    "Point to the .sig file, or paste the signature.", "error")
                return
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    signature = fh.read()
            except OSError as exc:
                self._verify_banner.show("Unreadable signature file: %s" % exc, "error")
                return

        expected_name = self._expected.selected_name()
        expected = None
        if expected_name:
            try:
                expected = self.app.keyring.public_key(expected_name)
            except Exception as exc:
                self._verify_banner.show(str(exc), "error")
                return

        def job(_report):
            with open(source, "rb") as fh:
                return verify_detached_stream(fh, signature, expected)

        def done(signer):
            fingerprint = signer.fingerprint_hex
            identity = self.app.keyring.find_by_fingerprint(fingerprint)
            if identity is not None:
                self._verify_banner.show(
                    "Signature VALID from \"%s\"  (%s)" % (identity.name, fingerprint),
                    "ok")
            else:
                self._verify_banner.show(
                    "Signature is mathematically valid, but fingerprint %s is not in "
                    "your keyring: you do not know whose it is." % fingerprint, "warn")
            self.app.status.message("Verification complete.", "ok")

        self.app.status.message("Verifying…")
        self.app.run(job, done, "Verification failed",
                     on_fail=lambda message: self._verify_banner.show(message, "error"))
