"""Reusable components shared by the application panels."""

from __future__ import annotations

from tkinter import filedialog
from typing import Callable, Iterable, List, Optional

import customtkinter as ctk

from . import theme
from .keyring import Identity

CRSYS_FILES = [("CRSYS containers", "*.crsys *.asc"), ("All files", "*.*")]
ALL_FILES = [("All files", "*.*")]
KEY_FILES = [("CRSYS keys", "*.pub *.key"), ("All files", "*.*")]


class Panel(ctk.CTkFrame):
    """Panel base class: holds the app reference and receives keyring refreshes."""

    def __init__(self, master, app) -> None:
        super().__init__(master, fg_color="transparent")
        self.app = app

    def on_identities_changed(self, identities: List[Identity]) -> None:
        """Called after every change to the keyring."""


def section(master, text: str) -> ctk.CTkLabel:
    label = ctk.CTkLabel(master, text=text, anchor="w",
                         font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold"))
    label.pack(fill="x", pady=(theme.PAD, 2))
    return label


def hint(master, text: str) -> ctk.CTkLabel:
    label = ctk.CTkLabel(master, text=text, anchor="w", justify="left",
                         text_color=theme.MUTED_FG, wraplength=560,
                         font=ctk.CTkFont(size=theme.SMALL_SIZE))
    label.pack(fill="x", pady=(2, 0))
    return label


class FilePicker(ctk.CTkFrame):
    """Path field with a Browse button, in open or save mode."""

    def __init__(self, master, mode: str = "open", title: str = "Choose a file",
                 filetypes=None, default_extension: str = "",
                 on_change: Optional[Callable] = None) -> None:
        super().__init__(master, fg_color="transparent")
        self._mode = mode
        self._title = title
        self._filetypes = filetypes or ALL_FILES
        self._default_extension = default_extension
        self._on_change = on_change

        self._entry = ctk.CTkEntry(self, placeholder_text="No file selected")
        self._entry.pack(side="left", fill="x", expand=True)
        if on_change:
            self._entry.bind("<KeyRelease>", lambda _e=None: on_change())
        ctk.CTkButton(self, text="Browse…", width=90, command=self._browse
                      ).pack(side="left", padx=(theme.PAD_S, 0))

    def _browse(self) -> None:
        if self._mode == "open":
            path = filedialog.askopenfilename(title=self._title,
                                              filetypes=self._filetypes, parent=self)
        else:
            path = filedialog.asksaveasfilename(
                title=self._title, filetypes=self._filetypes,
                defaultextension=self._default_extension, parent=self)
        if path:
            self.set(path)

    def get(self) -> str:
        return self._entry.get().strip()

    def set(self, path: str) -> None:
        self._entry.delete(0, "end")
        self._entry.insert(0, path)
        if self._on_change:
            self._on_change()


class IdentityChooser(ctk.CTkOptionMenu):
    """Identity dropdown, mapping display label back to the internal name."""

    NONE_LABEL = "— none —"

    def __init__(self, master, allow_none: bool = False,
                 command: Optional[Callable] = None, width: int = 260) -> None:
        super().__init__(master, values=[self.NONE_LABEL], width=width,
                         command=lambda _v: command() if command else None)
        self._allow_none = allow_none
        self._labels: dict = {}
        self.set(self.NONE_LABEL)

    def set_identities(self, identities: Iterable[Identity]) -> None:
        previous = self.selected_name()
        self._labels = {i.label: i.name for i in identities}
        values = ([self.NONE_LABEL] if self._allow_none else []) + list(self._labels)
        if not values:
            values = ["— no identities —"]
            self.configure(values=values, state="disabled")
            self.set(values[0])
            return

        self.configure(values=values, state="normal")
        for label, name in self._labels.items():
            if name == previous:
                self.set(label)
                return
        self.set(values[0])

    def selected_name(self) -> Optional[str]:
        return self._labels.get(self.get())


class RecipientPicker(ctk.CTkScrollableFrame):
    """Checkbox list: one container can have several recipients."""

    def __init__(self, master, height: int = 150) -> None:
        super().__init__(master, height=height, label_text="Recipients")
        self._boxes: dict = {}
        self._shape: Optional[tuple] = None
        self._empty: Optional[ctk.CTkLabel] = None

    @staticmethod
    def _shape_of(identities: List[Identity]) -> tuple:
        return tuple((i.name, i.fingerprint, i.has_private) for i in identities)

    def set_identities(self, identities: List[Identity]) -> None:
        # Two things keep Tk objects from being churned here, and both matter.
        #
        # This runs after every operation, via refresh_identities(), so the
        # rebuild is skipped when the identity list has not actually changed.
        #
        # And the checkboxes carry their own state rather than each owning a
        # StringVar. A StringVar is a Tk object with a __del__ that talks to the
        # interpreter, so collecting one on a worker thread raises "main thread
        # is not in main loop" from inside the garbage collector -- at a moment
        # nobody chose and nothing can catch.
        shape = self._shape_of(identities)
        if shape == self._shape:
            return

        selected = set(self.selected_names())
        for child in list(self.winfo_children()):
            child.destroy()
        self._boxes = {}
        self._shape = shape

        if not identities:
            self._empty = ctk.CTkLabel(
                self, text="No public keys in the keyring.\n"
                           "Create or import an identity in the Identities tab.",
                text_color=theme.MUTED_FG, justify="left",
                font=ctk.CTkFont(size=theme.SMALL_SIZE))
            self._empty.pack(anchor="w", padx=theme.PAD_S, pady=theme.PAD_S)
            return

        for identity in identities:
            suffix = "  (you)" if identity.has_private else ""
            box = ctk.CTkCheckBox(
                self, text="%s%s\n%s" % (identity.name, suffix, identity.fingerprint),
                font=ctk.CTkFont(size=theme.SMALL_SIZE))
            box.pack(anchor="w", padx=theme.PAD_S, pady=3)
            if identity.name in selected:
                box.select()
            self._boxes[identity.name] = box

    def selected_names(self) -> List[str]:
        return [name for name, box in self._boxes.items() if box.get()]

    def select(self, names: Iterable[str]) -> None:
        wanted = set(names)
        for name, box in self._boxes.items():
            if name in wanted:
                box.select()
            else:
                box.deselect()


class Banner(ctk.CTkFrame):
    """Coloured outcome box: green verified, amber partial, red rejected."""

    _STYLES = {
        "ok": (theme.OK_BG, theme.OK_FG),
        "warn": (theme.WARN_BG, theme.WARN_FG),
        "error": (theme.ERROR_BG, theme.ERROR_FG),
        "info": (theme.NEUTRAL_BG, theme.MUTED_FG),
    }

    def __init__(self, master) -> None:
        super().__init__(master, corner_radius=6, fg_color="transparent")
        self._label = ctk.CTkLabel(self, text="", anchor="w", justify="left",
                                   wraplength=620,
                                   font=ctk.CTkFont(size=theme.BODY_SIZE))
        self._label.pack(fill="x", padx=theme.PAD_S, pady=theme.PAD_S)
        self._visible = False

    def show(self, text: str, kind: str = "info") -> None:
        background, foreground = self._STYLES.get(kind, self._STYLES["info"])
        self.configure(fg_color=background)
        self._label.configure(text=text, text_color=foreground)
        if not self._visible:
            self.pack(fill="x", pady=(theme.PAD_S, 0))
            self._visible = True

    def clear(self) -> None:
        if self._visible:
            self.pack_forget()
            self._visible = False


class TextPanel(ctk.CTkFrame):
    """Monospaced text area with copy / paste / clear buttons."""

    def __init__(self, master, label: str, height: int = 140,
                 readonly: bool = False, actions: bool = True) -> None:
        super().__init__(master, fg_color="transparent")
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(header, text=label, anchor="w",
                     font=ctk.CTkFont(size=theme.BODY_SIZE, weight="bold")
                     ).pack(side="left")

        if actions:
            ctk.CTkButton(header, text="Clear", width=70, height=24,
                          fg_color="transparent", border_width=1,
                          font=ctk.CTkFont(size=theme.SMALL_SIZE),
                          command=self.clear).pack(side="right")
            if readonly:
                ctk.CTkButton(header, text="Copy", width=70, height=24,
                              font=ctk.CTkFont(size=theme.SMALL_SIZE),
                              command=self.copy).pack(side="right", padx=(0, 4))
            else:
                ctk.CTkButton(header, text="Paste", width=70, height=24,
                              font=ctk.CTkFont(size=theme.SMALL_SIZE),
                              command=self.paste).pack(side="right", padx=(0, 4))

        self._box = ctk.CTkTextbox(self, height=height, wrap="char",
                                   font=ctk.CTkFont(family=theme.MONO,
                                                    size=theme.SMALL_SIZE))
        self._box.pack(fill="both", expand=True, pady=(4, 0))
        self._readonly = readonly
        if readonly:
            self._box.configure(state="disabled")

    def get(self) -> str:
        return self._box.get("0.0", "end").strip()

    def set(self, text: str) -> None:
        if self._readonly:
            self._box.configure(state="normal")
        self._box.delete("0.0", "end")
        self._box.insert("0.0", text)
        if self._readonly:
            self._box.configure(state="disabled")

    def clear(self) -> None:
        self.set("")

    def copy(self) -> None:
        text = self.get()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)

    def paste(self) -> None:
        try:
            self.set(self.clipboard_get())
        except Exception:
            pass


class StatusBar(ctk.CTkFrame):
    """Status line with a determinate progress bar."""

    def __init__(self, master) -> None:
        super().__init__(master, height=32)
        self._label = ctk.CTkLabel(self, text="Ready", anchor="w",
                                   font=ctk.CTkFont(size=theme.SMALL_SIZE))
        self._label.pack(side="left", padx=theme.PAD)
        self._bar = ctk.CTkProgressBar(self, width=220)
        self._bar.set(0)

    def message(self, text: str, kind: str = "info") -> None:
        colors = {"ok": theme.OK_FG, "error": theme.ERROR_FG,
                  "warn": theme.WARN_FG, "info": theme.MUTED_FG}
        self._label.configure(text=text, text_color=colors.get(kind, theme.MUTED_FG))

    def progress(self, fraction: Optional[float]) -> None:
        if fraction is None:
            self._bar.pack_forget()
            return
        if not self._bar.winfo_ismapped():
            self._bar.pack(side="right", padx=theme.PAD)
        self._bar.set(max(0.0, min(1.0, fraction)))
