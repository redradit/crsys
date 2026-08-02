"""Modal windows: passphrase prompts, new identity, public key import."""

from __future__ import annotations

import os
from tkinter import messagebox
from typing import Optional

import customtkinter as ctk

from crsys import PublicKey

from . import theme
from .keyring import valid_name


class _Modal(ctk.CTkToplevel):
    """Base class for modal windows; the outcome lands in ``self.result``."""

    def __init__(self, parent, title: str, width: int = 420, height: int = 220) -> None:
        super().__init__(parent)
        self.result = None
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Escape>", lambda _e=None: self._cancel())

        parent.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - height) // 3
        self.geometry("%dx%d+%d+%d" % (width, height, max(x, 0), max(y, 0)))

        # grab_set() on a window that has not been mapped yet fails on Windows:
        # it expects the window manager to have actually shown it.
        self.after(120, self._make_modal)

    def _make_modal(self) -> None:
        try:
            self.grab_set()
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result


class PassphraseDialog(_Modal):
    """Ask for a passphrase, optionally with confirmation."""

    def __init__(self, parent, title: str, message: str, confirm: bool = False) -> None:
        super().__init__(parent, title, 460, 250 if confirm else 200)
        self._confirm = confirm

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        ctk.CTkLabel(frame, text=message, wraplength=410, justify="left",
                     font=ctk.CTkFont(size=theme.BODY_SIZE)).pack(anchor="w", pady=(0, 10))

        self._entry = ctk.CTkEntry(frame, show="•", width=420,
                                   placeholder_text="Passphrase")
        self._entry.pack(fill="x")
        self._entry.bind("<Return>", lambda _e=None: self._ok())

        self._entry2 = None
        if confirm:
            self._entry2 = ctk.CTkEntry(frame, show="•", width=420,
                                        placeholder_text="Repeat the passphrase")
            self._entry2.pack(fill="x", pady=(theme.PAD_S, 0))
            self._entry2.bind("<Return>", lambda _e=None: self._ok())

        self._error = ctk.CTkLabel(frame, text="", text_color=theme.ERROR_FG,
                                   font=ctk.CTkFont(size=theme.SMALL_SIZE))
        self._error.pack(anchor="w", pady=(theme.PAD_S, 0))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", side="bottom")
        ctk.CTkButton(buttons, text="Cancel", width=100, fg_color="transparent",
                      border_width=1, command=self._cancel).pack(side="right")
        ctk.CTkButton(buttons, text="OK", width=100,
                      command=self._ok).pack(side="right", padx=(0, theme.PAD_S))

        self.after(200, self._entry.focus_set)

    def _ok(self) -> None:
        value = self._entry.get()
        if not value:
            self._error.configure(text="The passphrase cannot be empty.")
            return
        if self._confirm and value != self._entry2.get():
            self._error.configure(text="The two passphrases do not match.")
            return
        self.result = value
        self.destroy()


class NewIdentityDialog(_Modal):
    """Name, label and passphrase for a new key pair."""

    def __init__(self, parent, existing_names) -> None:
        super().__init__(parent, "New identity", 480, 400)
        self._existing = set(existing_names)

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        ctk.CTkLabel(frame, text="Identity name",
                     font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold")).pack(anchor="w")
        self._name = ctk.CTkEntry(frame, placeholder_text="alice")
        self._name.pack(fill="x", pady=(2, 2))
        ctk.CTkLabel(frame, text="Becomes the file names alice.key and alice.pub.",
                     text_color=theme.MUTED_FG,
                     font=ctk.CTkFont(size=theme.SMALL_SIZE)).pack(anchor="w")

        ctk.CTkLabel(frame, text="Label (optional)",
                     font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold")
                     ).pack(anchor="w", pady=(theme.PAD, 0))
        self._comment = ctk.CTkEntry(frame, placeholder_text="Alice <alice@example.com>")
        self._comment.pack(fill="x", pady=(2, 0))

        ctk.CTkLabel(frame, text="Passphrase",
                     font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold")
                     ).pack(anchor="w", pady=(theme.PAD, 0))
        self._pass1 = ctk.CTkEntry(frame, show="•", placeholder_text="Passphrase")
        self._pass1.pack(fill="x", pady=(2, theme.PAD_S))
        self._pass2 = ctk.CTkEntry(frame, show="•",
                                   placeholder_text="Repeat the passphrase")
        self._pass2.pack(fill="x")

        self._none = ctk.CTkCheckBox(
            frame, text="Store the private key without a passphrase (not recommended)",
            font=ctk.CTkFont(size=theme.SMALL_SIZE), command=self._toggle_passphrase)
        self._none.pack(anchor="w", pady=(theme.PAD_S, 0))

        self._error = ctk.CTkLabel(frame, text="", text_color=theme.ERROR_FG,
                                   wraplength=440, justify="left",
                                   font=ctk.CTkFont(size=theme.SMALL_SIZE))
        self._error.pack(anchor="w", pady=(theme.PAD_S, 0))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", side="bottom")
        ctk.CTkButton(buttons, text="Cancel", width=100, fg_color="transparent",
                      border_width=1, command=self._cancel).pack(side="right")
        ctk.CTkButton(buttons, text="Generate", width=100,
                      command=self._ok).pack(side="right", padx=(0, theme.PAD_S))

        self.after(200, self._name.focus_set)

    def _toggle_passphrase(self) -> None:
        state = "disabled" if self._none.get() else "normal"
        self._pass1.configure(state=state)
        self._pass2.configure(state=state)

    def _ok(self) -> None:
        name = self._name.get().strip()
        if not valid_name(name):
            self._error.configure(
                text="Invalid name: letters, digits, dot, dash and underscore.")
            return
        if name in self._existing:
            self._error.configure(text="An identity with this name already exists.")
            return

        if self._none.get():
            passphrase = None
        else:
            passphrase = self._pass1.get()
            if not passphrase:
                self._error.configure(text="Enter a passphrase.")
                return
            if passphrase != self._pass2.get():
                self._error.configure(text="The two passphrases do not match.")
                return

        self.result = {
            "name": name,
            "comment": self._comment.get().strip(),
            "passphrase": passphrase,
        }
        self.destroy()


class NameDialog(_Modal):
    """Ask for a keyring name, checking that it can actually be used."""

    def __init__(self, parent, title: str, message: str, existing_names) -> None:
        super().__init__(parent, title, 440, 210)
        self._existing = set(existing_names)

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)
        ctk.CTkLabel(frame, text=message, wraplength=400, justify="left",
                     font=ctk.CTkFont(size=theme.BODY_SIZE)).pack(anchor="w")

        self._entry = ctk.CTkEntry(frame, placeholder_text="bob")
        self._entry.pack(fill="x", pady=(theme.PAD_S, 0))
        self._entry.bind("<Return>", lambda _e=None: self._ok())

        self._error = ctk.CTkLabel(frame, text="", text_color=theme.ERROR_FG,
                                   wraplength=400, justify="left",
                                   font=ctk.CTkFont(size=theme.SMALL_SIZE))
        self._error.pack(anchor="w", pady=(theme.PAD_S, 0))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", side="bottom")
        ctk.CTkButton(buttons, text="Cancel", width=100, fg_color="transparent",
                      border_width=1, command=self._cancel).pack(side="right")
        ctk.CTkButton(buttons, text="OK", width=100,
                      command=self._ok).pack(side="right", padx=(0, theme.PAD_S))
        self.after(200, self._entry.focus_set)

    def _ok(self) -> None:
        name = self._entry.get().strip()
        if not valid_name(name):
            self._error.configure(
                text="Invalid name: letters, digits, dot, dash and underscore.")
            return
        if name in self._existing:
            self._error.configure(text="That name is already used in the keyring.")
            return
        self.result = name
        self.destroy()


class ImportPublicDialog(_Modal):
    """Import a public key from a file or by pasting it (compact or armored)."""

    def __init__(self, parent, existing_names) -> None:
        super().__init__(parent, "Import public key", 560, 400)
        self._existing = set(existing_names)

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        ctk.CTkLabel(frame, text="Name to assign",
                     font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold")
                     ).pack(anchor="w")
        self._name = ctk.CTkEntry(frame, placeholder_text="bob")
        self._name.pack(fill="x", pady=(2, theme.PAD))

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(header, text="Public key",
                     font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold")
                     ).pack(side="left")
        ctk.CTkButton(header, text="Load from file…", width=130, height=24,
                      font=ctk.CTkFont(size=theme.SMALL_SIZE),
                      command=self._load_file).pack(side="right")

        self._text = ctk.CTkTextbox(frame, height=150, wrap="char",
                                    font=ctk.CTkFont(family=theme.MONO,
                                                     size=theme.SMALL_SIZE))
        self._text.pack(fill="both", expand=True, pady=(4, 0))

        ctk.CTkLabel(frame, text="Accepts the compact \"crsys1…\" form or a "
                                 "\"BEGIN CRSYS PUBLIC KEY\" block.",
                     text_color=theme.MUTED_FG, wraplength=520, justify="left",
                     font=ctk.CTkFont(size=theme.SMALL_SIZE)).pack(anchor="w", pady=(4, 0))

        self._error = ctk.CTkLabel(frame, text="", text_color=theme.ERROR_FG,
                                   wraplength=520, justify="left",
                                   font=ctk.CTkFont(size=theme.SMALL_SIZE))
        self._error.pack(anchor="w", pady=(theme.PAD_S, 0))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", side="bottom")
        ctk.CTkButton(buttons, text="Cancel", width=100, fg_color="transparent",
                      border_width=1, command=self._cancel).pack(side="right")
        ctk.CTkButton(buttons, text="Import", width=100,
                      command=self._ok).pack(side="right", padx=(0, theme.PAD_S))
        self.after(200, self._name.focus_set)

    def _load_file(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="CRSYS public key", parent=self,
            filetypes=[("Public keys", "*.pub"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            self._error.configure(text="Cannot read the file: %s" % exc)
            return
        self._text.delete("0.0", "end")
        self._text.insert("0.0", content)
        if not self._name.get().strip():
            stem = os.path.splitext(os.path.basename(path))[0]
            self._name.insert(0, stem)

    def _ok(self) -> None:
        name = self._name.get().strip()
        if not valid_name(name):
            self._error.configure(
                text="Invalid name: letters, digits, dot, dash and underscore.")
            return
        if name in self._existing:
            self._error.configure(text="That name is already used in the keyring.")
            return
        source = self._text.get("0.0", "end").strip()
        if not source:
            self._error.configure(text="Paste a public key or load one from a file.")
            return
        try:
            PublicKey.parse(source)
        except Exception as exc:
            self._error.configure(text="Invalid key: %s" % exc)
            return
        self.result = {"name": name, "source": source}
        self.destroy()


def ask_passphrase(parent, title: str, message: str,
                   confirm: bool = False) -> Optional[str]:
    return PassphraseDialog(parent, title, message, confirm).show()


def ask_name(parent, title: str, message: str, existing_names) -> Optional[str]:
    return NameDialog(parent, title, message, existing_names).show()


def ask_public_key(parent, existing_names) -> Optional[dict]:
    return ImportPublicDialog(parent, existing_names).show()


def ask_new_identity(parent, existing_names) -> Optional[dict]:
    return NewIdentityDialog(parent, existing_names).show()


def show_error(parent, title: str, message: str) -> None:
    messagebox.showerror(title, message, parent=parent)


def show_info(parent, title: str, message: str) -> None:
    messagebox.showinfo(title, message, parent=parent)


def ask_yes_no(parent, title: str, message: str) -> bool:
    return bool(messagebox.askyesno(title, message, parent=parent, default="no"))
