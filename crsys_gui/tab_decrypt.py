"""Decrypt tab: opens a container and reports the signature status."""

from __future__ import annotations

import io
import os
from typing import List

import customtkinter as ctk

from crsys import decrypt_bytes_verbose, decrypt_file, inspect_container

from . import dialogs, theme
from .keyring import Identity
from .widgets import (
    ALL_FILES,
    CRSYS_FILES,
    Banner,
    FilePicker,
    IdentityChooser,
    Panel,
    TextPanel,
    hint,
    section,
)


class DecryptPanel(Panel):
    def __init__(self, master, app) -> None:
        super().__init__(master, app)
        self._identities: List[Identity] = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0, minsize=310)
        self.grid_rowconfigure(0, weight=1)

        self._build_left()
        self._build_right()
        self._switch_mode("Text")

    # -------------------------------------------------------------------- UI

    def _build_left(self) -> None:
        left = ctk.CTkFrame(self)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, theme.PAD))
        inner = ctk.CTkFrame(left, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        self._mode = ctk.CTkSegmentedButton(inner, values=["Text", "File"],
                                            command=self._switch_mode)
        self._mode.set("Text")
        self._mode.pack(anchor="w")

        self._text_frame = ctk.CTkFrame(inner, fg_color="transparent")
        self._input_text = TextPanel(self._text_frame, "Encrypted message received",
                                    on_notice=self._notice,
                                     height=130)
        self._input_text.pack(fill="both", expand=True, pady=(theme.PAD, 0))
        self._output_text = TextPanel(self._text_frame, "Plaintext message",
                                      height=150, readonly=True)
        self._output_text.pack(fill="both", expand=True, pady=(theme.PAD, 0))

        self._file_frame = ctk.CTkFrame(inner, fg_color="transparent")
        section(self._file_frame, "Container to open")
        self._input_file = FilePicker(self._file_frame, mode="open",
                                      title="Encrypted file", filetypes=CRSYS_FILES,
                                      on_change=self._suggest_output)
        self._input_file.pack(fill="x")
        section(self._file_frame, "Save the contents to")
        self._output_file = FilePicker(self._file_frame, mode="save",
                                       title="Save the decrypted file",
                                       filetypes=ALL_FILES)
        self._output_file.pack(fill="x")

        self._banner = Banner(inner)

    def _build_right(self) -> None:
        right = ctk.CTkFrame(self)
        right.grid(row=0, column=1, sticky="nsew")
        inner = ctk.CTkFrame(right, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        section(inner, "Open with private key")
        self._key = IdentityChooser(inner, width=270)
        self._key.pack(fill="x")

        section(inner, "Expected sender")
        self._expected = IdentityChooser(inner, allow_none=True, width=270)
        self._expected.pack(fill="x")
        # Kept: without this, an unsigned message is accepted in silence.
        hint(inner, "Set this and decryption fails unless that exact key signed it.")

        section(inner, "Before opening")
        ctk.CTkButton(inner, text="Inspect container", height=32,
                      fg_color="transparent", border_width=1,
                      border_color=theme.BORDER, text_color=theme.TEXT_SECONDARY,
                      hover_color=theme.NEUTRAL_BG,
                      command=self._inspect).pack(fill="x")
        hint(inner, "Reads the metadata without using a key.")

        self._button = ctk.CTkButton(inner, text="Decrypt", height=40,
                                     font=ctk.CTkFont(size=theme.TITLE_SIZE,
                                                      weight="bold"),
                                     command=self._decrypt)
        self._button.pack(fill="x", side="bottom", pady=(theme.PAD, 0))

    # ------------------------------------------------------------------ state

    def on_identities_changed(self, identities: List[Identity]) -> None:
        self._identities = identities
        self._key.set_identities(
            [i for i in identities if i.has_private and not i.error])
        self._expected.set_identities([i for i in identities if i.public_key])

    def _switch_mode(self, mode: str) -> None:
        self._banner.clear()
        if mode == "Text":
            self._file_frame.pack_forget()
            self._text_frame.pack(fill="both", expand=True)
        else:
            self._text_frame.pack_forget()
            self._file_frame.pack(fill="both", expand=True)

    def _suggest_output(self) -> None:
        source = self._input_file.get()
        if not source or self._output_file.get():
            return
        base, ext = os.path.splitext(source)
        self._output_file.set(base if ext in (".crsys", ".asc") else source + ".out")

    # --------------------------------------------------------------- inspect

    def _inspect(self) -> None:
        try:
            if self._mode.get() == "Text":
                payload = self._input_text.get().encode("utf-8")
                if not payload:
                    self._banner.show("Paste an encrypted message first.", "error")
                    return
                info = inspect_container(io.BytesIO(payload))
            else:
                path = self._input_file.get()
                if not path or not os.path.isfile(path):
                    self._banner.show("Choose a file first.", "error")
                    return
                with open(path, "rb") as fh:
                    info = inspect_container(fh)
        except Exception as exc:
            self._banner.show("Not a readable CRSYS container: %s" % exc, "error")
            return

        recipients = []
        for fingerprint in info["recipients"]:
            identity = (self.app.keyring.find_by_fingerprint(fingerprint)
                        if fingerprint != "anonymous" else None)
            recipients.append("%s%s" % (fingerprint,
                                        "  (%s)" % identity.name if identity else ""))

        self._banner.show(
            "Version %d · %s · %s\nRecipients (%d): %s"
            % (info["version"], info["suite"],
               "signed" if info["signed"] else "NOT signed",
               len(recipients), ", ".join(recipients)),
            "info" if info["signed"] else "warn")

    # ----------------------------------------------------------------- action

    def _decrypt(self) -> None:
        self._banner.clear()
        key_name = self._key.selected_name()
        if not key_name:
            self._banner.show("A private key is required in the keyring.", "error")
            return

        proceed, passphrase = self.app.ask_unlock(key_name)
        if not proceed:
            return

        expected_name = self._expected.selected_name()
        expected = None
        if expected_name:
            try:
                expected = self.app.keyring.public_key(expected_name)
            except Exception as exc:
                self._banner.show(str(exc), "error")
                return

        text_mode = self._mode.get() == "Text"
        if text_mode:
            payload = self._input_text.get()
            if not payload:
                self._banner.show("Paste the encrypted message.", "error")
                return
            data = payload.encode("utf-8")
        else:
            source = self._input_file.get()
            destination = self._output_file.get()
            if not source or not os.path.isfile(source):
                self._banner.show("Choose the file to decrypt.", "error")
                return
            if not destination:
                self._banner.show("Say where the contents should go.", "error")
                return
            if os.path.abspath(source) == os.path.abspath(destination):
                self._banner.show("Source and destination are the same file.", "error")
                return
            if os.path.exists(destination) and not dialogs.ask_yes_no(
                    self.app, "Overwrite?",
                    '"%s" already exists. Overwrite it?'
                    % os.path.basename(destination)):
                return

        def job(report):
            keypair = self.app.keypair(key_name, passphrase)
            if text_mode:
                return decrypt_bytes_verbose(data, keypair, expected)
            return decrypt_file(source, destination, keypair, expected, progress=report)

        def done(result):
            if text_mode:
                plaintext, info = result
                try:
                    self._output_text.set(plaintext.decode("utf-8"))
                except UnicodeDecodeError:
                    self._output_text.set("")
                    self._banner.show(
                        "Decrypted correctly, but the content is not text (%d bytes). "
                        "Use File mode to save it." % len(plaintext), "warn")
                    self.app.status.message("Decrypted: binary content.", "ok")
                    return
            else:
                info = result

            self._show_signature(info, None if text_mode else destination)
            self.app.status.message("Decryption complete.", "ok")

        self.app.status.message("Decrypting…")
        self.app.run(job, done, "Decryption failed",
                     on_fail=lambda message: self._banner.show(message, "error"),
                     progress=True)

    def _show_signature(self, info, destination) -> None:
        """The most important line in the interface: who actually wrote this."""
        saved = "\nSaved to %s" % destination if destination else ""

        if info.signer is None:
            self._banner.show(
                "Content decrypted, but the message is NOT signed: there is no proof "
                "of who wrote it. Anyone who knows your public key could have "
                "produced it." + saved, "warn")
            return

        fingerprint = info.signer_fingerprint
        # Resolved by full public key, never by fingerprint: putting a name next
        # to a signature is an identity decision, and 64 bits is not enough to
        # make one on.
        identity = self.app.keyring.find_by_public_key(info.signer)
        if identity is not None:
            self._banner.show(
                'Valid signature from "%s"  (%s)%s'
                % (identity.name, fingerprint, saved), "ok")
        else:
            self._banner.show(
                "Signature is mathematically valid, but fingerprint %s is not in "
                "your keyring: you do not know whose it is.%s" % (fingerprint, saved),
                "warn")
