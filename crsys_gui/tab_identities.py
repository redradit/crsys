"""Identities tab: keyring management."""

from __future__ import annotations

import tkinter
from tkinter import filedialog
from typing import List, Optional

import customtkinter as ctk

from crsys import KeyPair

from . import dialogs, theme
from .keyring import Identity
from .widgets import Panel, section


def _ghost_button(master, text: str, command) -> ctk.CTkButton:
    """A secondary action: no fill, no border, weight carried by the label alone."""
    return ctk.CTkButton(master, text=text, height=34, fg_color="transparent",
                         hover_color=theme.NEUTRAL_BG,
                         text_color=theme.TEXT_SECONDARY,
                         command=command)


class IdentityRow(ctk.CTkFrame):
    """One list row: name, fingerprint and state, clickable as a whole."""

    def __init__(self, master, identity: Identity, on_click, selected: bool) -> None:
        super().__init__(master, corner_radius=6,
                         fg_color=theme.SELECTED_BG if selected else "transparent")
        self._selected = selected

        name = ctk.CTkLabel(self, text=identity.name, anchor="w",
                            font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold"))
        name.pack(fill="x", padx=theme.PAD_S, pady=(theme.PAD_S, 0))

        detail = ctk.CTkLabel(
            self, text="%s  ·  %s" % (identity.fingerprint, identity.kind),
            anchor="w", text_color=theme.ERROR_FG if identity.error else theme.MUTED_FG,
            font=ctk.CTkFont(family=theme.MONO, size=theme.SMALL_SIZE))
        detail.pack(fill="x", padx=theme.PAD_S, pady=(0, theme.PAD_S))

        for widget in (self, name, detail):
            widget.bind("<Button-1>", lambda _e=None, n=identity.name: on_click(n))
            widget.bind("<Enter>", self._enter)
            widget.bind("<Leave>", self._leave)

    def _enter(self, _event=None) -> None:
        if not self._selected:
            self.configure(fg_color=theme.CARD_BG)

    def _leave(self, _event=None) -> None:
        if not self._selected:
            self.configure(fg_color="transparent")


class IdentitiesPanel(Panel):
    def __init__(self, master, app) -> None:
        super().__init__(master, app)
        self._identities: List[Identity] = []
        self._selected: Optional[str] = None

        self.grid_columnconfigure(0, weight=0, minsize=320)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_left()
        self._build_right()

    # -------------------------------------------------------------------- UI

    def _build_left(self) -> None:
        left = ctk.CTkFrame(self)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, theme.PAD))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        toolbar = ctk.CTkFrame(left, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=theme.PAD_S,
                     pady=(theme.PAD_S, 0))
        ctk.CTkButton(toolbar, text="+  Generate", height=30,
                      command=self._generate).pack(side="left")
        # Kept as an attribute: the menu is positioned under this button rather
        # than at a hardcoded offset, which silently went wrong when the layout
        # changed.
        self._import_button = ctk.CTkButton(
            toolbar, text="Import…", height=30, width=90,
            fg_color="transparent", border_width=1, border_color=theme.BORDER,
            text_color=theme.TEXT_SECONDARY, hover_color=theme.NEUTRAL_BG,
            command=self._import_menu)
        self._import_button.pack(side="left", padx=(theme.PAD_S, 0))

        self._list = ctk.CTkScrollableFrame(left, fg_color="transparent")
        self._list.grid(row=1, column=0, sticky="nsew", padx=theme.PAD_S,
                        pady=theme.PAD_S)

        self._lock_all = ctk.CTkButton(
            left, text="Lock all keys", height=28, fg_color="transparent",
            border_width=1, font=ctk.CTkFont(size=theme.SMALL_SIZE),
            command=self._lock_all_keys)
        self._lock_all.grid(row=2, column=0, sticky="ew", padx=theme.PAD_S,
                            pady=(0, theme.PAD_S))

    def _build_right(self) -> None:
        right = ctk.CTkFrame(self)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)

        self._detail = ctk.CTkFrame(right, fg_color="transparent")
        self._detail.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        self._empty = ctk.CTkLabel(
            self._detail, justify="left", text_color=theme.MUTED_FG,
            text="Select an identity on the left.\n\n"
                 "An identity is a key pair:\n"
                 "  ·  the public key is meant to be handed out freely\n"
                 "  ·  the private key stays on your disk,"
                 " protected by a passphrase\n\n"
                 "Anyone who wants to write to you only needs your public key.",
            font=ctk.CTkFont(size=theme.BODY_SIZE))
        self._empty.pack(anchor="w")

        self._card = ctk.CTkFrame(self._detail, fg_color="transparent")

        self._title = ctk.CTkLabel(self._card, text="", anchor="w",
                                   text_color=theme.TEXT_PRIMARY,
                                   font=ctk.CTkFont(size=theme.SIZE_DISPLAY,
                                                    weight="bold"))
        self._title.pack(fill="x")
        self._subtitle = ctk.CTkLabel(self._card, text="", anchor="w",
                                      text_color=theme.MUTED_FG,
                                      font=ctk.CTkFont(size=theme.SIZE_BODY))
        self._subtitle.pack(fill="x", pady=(theme.SPACE_XS, theme.SPACE_L))

        # Two facts, not four. The label already appears as the subtitle above,
        # and the file names are developer trivia -- listing them made the panel
        # read as a debug dump rather than a description of an identity.
        self._fields = ctk.CTkFrame(self._card, fg_color="transparent")
        self._fields.pack(fill="x")
        self._fields.grid_columnconfigure(1, weight=1)

        self._value_widgets = {}
        for row, label in enumerate(("Fingerprint", "State")):
            ctk.CTkLabel(self._fields, text=label.upper(), anchor="w", width=96,
                         text_color=theme.MUTED_FG,
                         font=ctk.CTkFont(size=theme.SIZE_CAPTION, weight="bold")
                         ).grid(row=row, column=0, sticky="w",
                                pady=(0, theme.SPACE_S))
            # Monospace only where the characters must be compared one by one.
            family = theme.MONO if label == "Fingerprint" else None
            value = ctk.CTkLabel(self._fields, text="", anchor="w", justify="left",
                                 text_color=theme.TEXT_PRIMARY,
                                 font=ctk.CTkFont(family=family,
                                                  size=theme.SIZE_BODY))
            value.grid(row=row, column=1, sticky="ew", pady=(0, theme.SPACE_S))
            self._value_widgets[label] = value

        section(self._card, "PUBLIC KEY, COMPACT FORM")
        # Bounded rather than stretched: a base64 key spread across a maximised
        # window is harder to read, not easier.
        compact_row = ctk.CTkFrame(self._card, fg_color="transparent")
        compact_row.pack(fill="x")
        self._compact = ctk.CTkEntry(compact_row, width=620, height=34,
                                     font=ctk.CTkFont(family=theme.MONO,
                                                      size=theme.SIZE_CAPTION))
        self._compact.pack(side="left")
        ctk.CTkButton(compact_row, text="Copy", width=84, height=34,
                      command=self._copy_compact).pack(side="left",
                                                       padx=(theme.SPACE_S, 0))
        ctk.CTkLabel(self._card,
                     text="Send this to whoever needs to write to you. Have them "
                          "confirm the fingerprint over a different channel — voice, "
                          "in person. The software cannot do that for you.",
                     anchor="w", justify="left", wraplength=560,
                     text_color=theme.MUTED_FG,
                     font=ctk.CTkFont(size=theme.SIZE_CAPTION)
                     ).pack(fill="x", pady=(theme.SPACE_S, 0))

        # One filled button carries the primary action; the rest are quiet text
        # buttons. Three outlined boxes in a row gave every action the same
        # weight, which is the same as giving none of them any.
        actions = ctk.CTkFrame(self._card, fg_color="transparent")
        actions.pack(fill="x", pady=(theme.SPACE_L, 0))
        self._btn_unlock = ctk.CTkButton(actions, text="Unlock", width=130, height=34,
                                         command=self._toggle_lock)
        self._btn_unlock.pack(side="left")
        self._btn_passwd = _ghost_button(actions, "Change passphrase",
                                         self._change_passphrase)
        self._btn_passwd.pack(side="left", padx=(theme.SPACE_S, 0))
        self._btn_export = _ghost_button(actions, "Export public…",
                                         self._export_public)
        self._btn_export.pack(side="left")

        ctk.CTkButton(self._card, text="Delete identity", width=130, height=30,
                      fg_color="transparent", hover_color=theme.ERROR_BG,
                      text_color=theme.ERROR_FG, anchor="w",
                      font=ctk.CTkFont(size=theme.SIZE_CAPTION),
                      command=self._delete).pack(anchor="w",
                                                 pady=(theme.SPACE_XL, 0))

    # ------------------------------------------------------------------ data

    def on_identities_changed(self, identities: List[Identity]) -> None:
        self._identities = identities
        names = {i.name for i in identities}
        if self._selected not in names:
            self._selected = identities[0].name if identities else None

        for child in list(self._list.winfo_children()):
            child.destroy()
        for identity in identities:
            row = IdentityRow(self._list, identity, self._select,
                              identity.name == self._selected)
            row.pack(fill="x", pady=2)

        unlocked = self.app.keyring.unlocked_names()
        self._lock_all.configure(
            text="Lock all keys (%d unlocked)" % len(unlocked)
            if unlocked else "No unlocked keys",
            state="normal" if unlocked else "disabled")
        self._render_detail()

    def _current(self) -> Optional[Identity]:
        for identity in self._identities:
            if identity.name == self._selected:
                return identity
        return None

    def _select(self, name: str) -> None:
        self._selected = name
        self.on_identities_changed(self._identities)

    def _render_detail(self) -> None:
        identity = self._current()
        if identity is None:
            self._card.pack_forget()
            self._empty.pack(anchor="w")
            return
        self._empty.pack_forget()
        self._card.pack(fill="both", expand=True)

        self._title.configure(text=identity.name)
        self._subtitle.configure(text=identity.comment or "no label")

        state = identity.error or {
            "public only": "Public key only — you can encrypt to it, not sign as it",
            "private": "Private key locked"
            + ("" if identity.encrypted else " — stored WITHOUT a passphrase"),
            "unlocked": "Private key unlocked in memory",
            "unreadable": "Damaged file",
        }.get(identity.kind, identity.kind)

        self._value_widgets["Fingerprint"].configure(text=identity.fingerprint)
        self._value_widgets["State"].configure(
            text=state,
            text_color=theme.ERROR_FG if identity.error else
            theme.OK_FG if identity.unlocked else theme.TEXT_SECONDARY)

        self._compact.configure(state="normal")
        self._compact.delete(0, "end")
        if identity.public_key:
            self._compact.insert(0, identity.public_key.to_compact())
        self._compact.configure(state="readonly")

        has_private = identity.has_private and not identity.error
        self._btn_unlock.configure(
            text="Lock" if identity.unlocked else "Unlock",
            state="normal" if has_private else "disabled")
        self._btn_passwd.configure(state="normal" if has_private else "disabled")
        self._btn_export.configure(
            state="normal" if identity.public_key else "disabled")

    # --------------------------------------------------------------- actions

    def _generate(self) -> None:
        data = dialogs.ask_new_identity(self.app,
                                        [i.name for i in self._identities])
        if not data:
            return
        passphrase = data["passphrase"]
        secret = passphrase.encode("utf-8") if passphrase else None
        self.app.status.message("Generating the key pair…")

        def job(_report):
            return self.app.keyring.create(data["name"], data["comment"], secret)

        def done(identity):
            self._selected = identity.name
            self.app.status.message('Identity "%s" created.' % identity.name, "ok")
            self.app.refresh_identities()

        self.app.run(job, done, "Could not create the identity")

    def build_import_menu(self) -> tkinter.Menu:
        """The Import menu, built but not posted, so it can be tested."""
        menu = tkinter.Menu(
            self, tearoff=0, borderwidth=0, activeborderwidth=0,
            bg=self._apply_appearance_mode(theme.SURFACE_RAISED),
            fg=self._apply_appearance_mode(theme.TEXT_PRIMARY),
            activebackground=self._apply_appearance_mode(theme.ACCENT),
            activeforeground="#FFFFFF",
            font=("", theme.SIZE_BODY))
        menu.add_command(label="  Public key…  ", command=self._import_public)
        menu.add_command(label="  Private key…  ", command=self._import_private)
        return menu

    def _import_menu(self) -> None:
        """Post the Import menu under its button.

        This used to be a hand-rolled CTkToplevel that closed itself on
        <FocusOut>. Pressing an entry moved focus, so the popup destroyed itself
        on mouse-down and the button was gone before its command could run on
        mouse-up: the menu appeared, and choosing from it did nothing. Tk's own
        menu already handles focus, grabs and dismissal, and gets them right.
        """
        menu = self.build_import_menu()
        button = self._import_button
        x = button.winfo_rootx()
        y = button.winfo_rooty() + button.winfo_height() + 2
        try:
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()

    def _import_public(self) -> None:
        data = dialogs.ask_public_key(self.app, [i.name for i in self._identities])
        if not data:
            return
        try:
            self.app.keyring.import_public(data["source"], data["name"])
        except Exception as exc:
            dialogs.show_error(self.app, "Import failed", str(exc))
            return
        self._selected = data["name"]
        self.app.status.message('Public key "%s" imported.' % data["name"], "ok")
        self.app.refresh_identities()

    def _import_private(self) -> None:
        path = filedialog.askopenfilename(
            title="CRSYS private key", parent=self.app,
            filetypes=[("Private keys", "*.key"), ("All files", "*.*")])
        if not path:
            return
        name = dialogs.ask_name(
            self.app, "Import private key",
            "Under what name should it be stored in the keyring?",
            [i.name for i in self._identities])
        if not name:
            return

        passphrase = None
        try:
            if KeyPair.is_encrypted(path):
                value = dialogs.ask_passphrase(
                    self.app, "Passphrase",
                    "Passphrase of the private key being imported:")
                if value is None:
                    return
                passphrase = value.encode("utf-8")
        except Exception as exc:
            dialogs.show_error(self.app, "Unreadable file", str(exc))
            return

        self.app.status.message("Importing…")

        def job(_report):
            return self.app.keyring.import_private(path, name, passphrase)

        def done(identity):
            self._selected = identity.name
            self.app.status.message('Private key "%s" imported.' % name, "ok")
            self.app.refresh_identities()

        self.app.run(job, done, "Import failed")

    def _toggle_lock(self) -> None:
        identity = self._current()
        if identity is None:
            return
        if identity.unlocked:
            self.app.keyring.lock(identity.name)
            self.app.status.message('Key "%s" locked.' % identity.name)
            self.app.refresh_identities()
            return

        passphrase = None
        if identity.encrypted:
            value = dialogs.ask_passphrase(
                self.app, 'Unlock "%s"' % identity.name,
                "Enter the passphrase for this private key.")
            if value is None:
                return
            passphrase = value.encode("utf-8")

        self.app.status.message("Deriving the key…")

        def job(_report):
            return self.app.keyring.unlock(identity.name, passphrase)

        def done(_keypair):
            self.app.status.message('Key "%s" unlocked.' % identity.name, "ok")
            self.app.refresh_identities()

        self.app.run(job, done, "Unlock failed")

    def _lock_all_keys(self) -> None:
        count = self.app.keyring.lock_all()
        self.app.status.message("%d keys removed from memory." % count)
        self.app.refresh_identities()

    def _change_passphrase(self) -> None:
        identity = self._current()
        if identity is None:
            return

        old = None
        if identity.encrypted and not identity.unlocked:
            value = dialogs.ask_passphrase(self.app, "Current passphrase",
                                           "Enter the current passphrase.")
            if value is None:
                return
            old = value.encode("utf-8")

        value = dialogs.ask_passphrase(
            self.app, "New passphrase",
            'Choose the new passphrase for "%s".' % identity.name, confirm=True)
        if value is None:
            return
        new = value.encode("utf-8")

        cached = self.app.keyring.cached(identity.name)
        self.app.status.message("Rewriting the key…")

        def job(_report):
            if cached is not None:
                cached.save(identity.key_path, new)
            else:
                self.app.keyring.change_passphrase(identity.name, old, new)
            return None

        def done(_result):
            self.app.status.message(
                'Passphrase for "%s" updated.' % identity.name, "ok")
            self.app.refresh_identities()

        self.app.run(job, done, "Could not change the passphrase")

    def _export_public(self) -> None:
        identity = self._current()
        if identity is None or identity.public_key is None:
            return
        path = filedialog.asksaveasfilename(
            title="Export public key", parent=self.app,
            initialfile=identity.name + ".pub", defaultextension=".pub",
            filetypes=[("Public keys", "*.pub"), ("All files", "*.*")])
        if not path:
            return
        try:
            identity.public_key.save(path)
        except OSError as exc:
            dialogs.show_error(self.app, "Export failed", str(exc))
            return
        self.app.status.message("Public key saved to %s" % path, "ok")

    def _copy_compact(self) -> None:
        identity = self._current()
        if identity is None or identity.public_key is None:
            return
        self.clipboard_clear()
        self.clipboard_append(identity.public_key.to_compact())
        self.app.status.message("Public key copied to the clipboard.", "ok")

    def _delete(self) -> None:
        identity = self._current()
        if identity is None:
            return
        if identity.has_private:
            message = ('Delete "%s"?\n\nThis includes the PRIVATE KEY: without a '
                       "backup, every message encrypted to this identity becomes "
                       "permanently unreadable." % identity.name)
        else:
            message = 'Delete the public key "%s"?' % identity.name
        if not dialogs.ask_yes_no(self.app, "Confirm deletion", message):
            return
        try:
            self.app.keyring.delete(identity.name)
        except Exception as exc:
            dialogs.show_error(self.app, "Deletion failed", str(exc))
            return
        self._selected = None
        self.app.status.message('Identity "%s" deleted.' % identity.name)
        self.app.refresh_identities()
