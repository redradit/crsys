"""Encrypt tab: from text or from a file, for one or more recipients."""

from __future__ import annotations

import os
from typing import List

import customtkinter as ctk

from crsys import SUITE_BY_NAME, encrypt_bytes, encrypt_file

from . import dialogs, theme
from .keyring import Identity
from .widgets import (
    ALL_FILES,
    CRSYS_FILES,
    Banner,
    FilePicker,
    IdentityChooser,
    Panel,
    RecipientPicker,
    TextPanel,
    hint,
    section,
)

SUITE_LABELS = {
    "ChaCha20-Poly1305 (default)": "chacha20poly1305",
    "AES-256-GCM": "aes256gcm",
}


class EncryptPanel(Panel):
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

        # --- text mode
        self._text_frame = ctk.CTkFrame(inner, fg_color="transparent")
        self._input_text = TextPanel(self._text_frame, "Plaintext message", height=130)
        self._input_text.pack(fill="both", expand=True, pady=(theme.PAD, 0))
        self._output_text = TextPanel(self._text_frame, "Encrypted message",
                                      height=150, readonly=True)
        self._output_text.pack(fill="both", expand=True, pady=(theme.PAD, 0))

        # --- file mode
        self._file_frame = ctk.CTkFrame(inner, fg_color="transparent")
        section(self._file_frame, "File to encrypt")
        self._input_file = FilePicker(self._file_frame, mode="open",
                                      title="File to encrypt", filetypes=ALL_FILES,
                                      on_change=self._suggest_output)
        self._input_file.pack(fill="x")
        section(self._file_frame, "Save the container to")
        self._output_file = FilePicker(self._file_frame, mode="save",
                                       title="Save the encrypted file",
                                       filetypes=CRSYS_FILES,
                                       default_extension=".crsys")
        self._output_file.pack(fill="x")

        self._banner = Banner(inner)

    def _build_right(self) -> None:
        right = ctk.CTkFrame(self)
        right.grid(row=0, column=1, sticky="nsew")
        inner = ctk.CTkFrame(right, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        self._recipients = RecipientPicker(inner, height=170)
        self._recipients.pack(fill="both", expand=True)

        section(inner, "Sign with")
        self._signer = IdentityChooser(inner, allow_none=True, width=270)
        self._signer.pack(fill="x")
        # Kept: this one prevents a security mistake rather than explaining a control.
        hint(inner, "Unsigned, the recipient can read it but cannot prove you wrote it.")

        section(inner, "Options")
        self._armor = ctk.CTkCheckBox(inner, text="ASCII output (for email)",
                                      font=ctk.CTkFont(size=theme.SMALL_SIZE),
                                      command=self._suggest_output)
        self._armor.pack(anchor="w", pady=2)
        self._hide = ctk.CTkCheckBox(inner, text="Hide recipient fingerprints",
                                     font=ctk.CTkFont(size=theme.SMALL_SIZE))
        self._hide.pack(anchor="w", pady=2)

        self._suite = ctk.CTkOptionMenu(inner, values=list(SUITE_LABELS), width=270)
        self._suite.set(list(SUITE_LABELS)[0])
        self._suite.pack(fill="x", pady=(theme.PAD_S, 0))

        self._button = ctk.CTkButton(inner, text="Encrypt", height=40,
                                     font=ctk.CTkFont(size=theme.TITLE_SIZE,
                                                      weight="bold"),
                                     command=self._encrypt)
        self._button.pack(fill="x", side="bottom", pady=(theme.PAD, 0))

    # ------------------------------------------------------------------ state

    def on_identities_changed(self, identities: List[Identity]) -> None:
        self._identities = identities
        self._recipients.set_identities([i for i in identities if i.public_key])
        self._signer.set_identities([i for i in identities
                                     if i.has_private and not i.error])

    def _switch_mode(self, mode: str) -> None:
        self._banner.clear()
        if mode == "Text":
            self._file_frame.pack_forget()
            self._text_frame.pack(fill="both", expand=True)
            # A binary container inside a text box cannot be pasted anywhere
            # useful, so ASCII armor is mandatory in text mode.
            self._armor.select()
            self._armor.configure(state="disabled")
        else:
            self._text_frame.pack_forget()
            self._file_frame.pack(fill="both", expand=True)
            self._armor.configure(state="normal")

    def _suggest_output(self) -> None:
        source = self._input_file.get()
        if not source or self._output_file.get():
            return
        extension = ".asc" if self._armor.get() else ".crsys"
        self._output_file.set(source + extension)

    # ----------------------------------------------------------------- action

    def _encrypt(self) -> None:
        self._banner.clear()
        recipients = self._recipients.selected_names()
        if not recipients:
            self._banner.show("Select at least one recipient.", "error")
            return

        try:
            keys = [self.app.keyring.public_key(name) for name in recipients]
        except Exception as exc:
            self._banner.show(str(exc), "error")
            return

        signer_name = self._signer.selected_name()
        passphrase = None
        if signer_name:
            proceed, passphrase = self.app.ask_unlock(signer_name)
            if not proceed:
                return

        suite = SUITE_BY_NAME[SUITE_LABELS[self._suite.get()]]
        hide = bool(self._hide.get())
        armored = bool(self._armor.get())
        text_mode = self._mode.get() == "Text"

        if text_mode:
            payload = self._input_text.get()
            if not payload:
                self._banner.show("Write a message to encrypt.", "error")
                return
            data = payload.encode("utf-8")
        else:
            source = self._input_file.get()
            destination = self._output_file.get()
            if not source or not os.path.isfile(source):
                self._banner.show("Choose a file to encrypt.", "error")
                return
            if not destination:
                self._banner.show("Say where the encrypted file should go.", "error")
                return
            if os.path.abspath(source) == os.path.abspath(destination):
                self._banner.show("Source and destination are the same file.", "error")
                return
            if os.path.exists(destination) and not dialogs.ask_yes_no(
                    self.app, "Overwrite?",
                    "\"%s\" already exists. Overwrite it?"
                    % os.path.basename(destination)):
                return

        def job(report):
            signer = (self.app.keypair(signer_name, passphrase)
                      if signer_name else None)
            if text_mode:
                return encrypt_bytes(data, keys, signer=signer, suite=suite,
                                     hide_recipients=hide, armored=True)
            return encrypt_file(source, destination, keys, signer=signer, suite=suite,
                                hide_recipients=hide, armored=armored, progress=report)

        def done(result):
            names = ", ".join(recipients)
            if text_mode:
                self._output_text.set(result)
                self._banner.show(
                    "Message encrypted for %s%s. Copy it and send it over any "
                    "channel, safe or not."
                    % (names, " and signed" if signer_name else ""), "ok")
            else:
                self._banner.show(
                    "Done: %s bytes -> %s bytes, for %s%s.\nSaved to %s"
                    % (result.plaintext_bytes, result.ciphertext_bytes, names,
                       " (signed)" if signer_name else "", destination), "ok")
            self.app.status.message("Encryption complete.", "ok")
            self.app.refresh_identities()

        self.app.status.message("Encrypting…")
        self.app.run(job, done, "Encryption failed",
                     on_fail=lambda message: self._banner.show(message, "error"),
                     progress=True)
