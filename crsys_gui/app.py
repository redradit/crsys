"""CRSYS main window."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import traceback
from typing import Callable, Optional, Tuple

import customtkinter as ctk

from crsys import __version__
from crsys.errors import CrsysError

from . import dialogs, theme
from .keyring import DEFAULT_DIR, Keyring
from .tab_decrypt import DecryptPanel
from .tab_encrypt import EncryptPanel
from .tab_identities import IdentitiesPanel
from .tab_sign import SignPanel
from .tasks import TaskRunner
from .widgets import StatusBar

APPEARANCE_MODES = ("System", "Light", "Dark")
AUTOLOCK_SECONDS = 10 * 60
SETTINGS_FILE = "gui.json"


class CrsysApp(ctk.CTk):
    def __init__(self, keyring_dir: Optional[str] = None) -> None:
        super().__init__()

        self.keyring = Keyring(keyring_dir or DEFAULT_DIR)
        self._settings = self._load_settings()
        if self._settings.get("appearance") not in APPEARANCE_MODES:
            self._settings["appearance"] = "System"
        ctk.set_appearance_mode(self._settings["appearance"])
        ctk.set_default_color_theme("blue")
        theme.apply()  # must run before any widget is constructed

        self.title("CRSYS  —  public-key encryption")
        self.geometry(self._settings.get("geometry", "1120x740"))
        self.minsize(940, 640)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.tasks = TaskRunner(self)
        self._last_activity = time.monotonic()
        self._autolock_id = None
        self._closing = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_tabs()
        self._build_status()

        self.bind_all("<Button-1>", lambda _e: self.touch(), add="+")
        self.bind_all("<Key>", lambda _e: self.touch(), add="+")
        self._autolock_id = self.after(30000, self._check_autolock)

        self.refresh_identities()

    # -------------------------------------------------------------- shutdown

    def destroy(self) -> None:
        """Stop the timers before tearing the widget tree down.

        An ``after`` callback firing on destroyed widgets produces noisy and
        entirely useless Tcl errors.
        """
        self._closing = True
        self.tasks.stop()
        if self._autolock_id is not None:
            try:
                self.after_cancel(self._autolock_id)
            except Exception:
                pass
            self._autolock_id = None
        try:
            super().destroy()
        except Exception:
            # CustomTkinter can trip over an already-removed Tcl command while
            # unwinding. The window is gone either way, and surfacing an error
            # during shutdown would just be noise.
            try:
                self.quit()
            except Exception:
                pass

    def report_callback_exception(self, exc, value, tb) -> None:
        if self._closing:
            return
        traceback.print_exception(exc, value, tb)

    # ------------------------------------------------------------------ build

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=0, fg_color=theme.SURFACE_RAISED)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        # Wordmark, with the version as a quiet subscript rather than a peer.
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w",
                  padx=(theme.SPACE_L, theme.SPACE_M), pady=theme.SPACE_M)
        ctk.CTkLabel(left, text="CRSYS", anchor="w", text_color=theme.TEXT_PRIMARY,
                     font=ctk.CTkFont(size=theme.SIZE_DISPLAY, weight="bold")
                     ).pack(side="left")
        ctk.CTkLabel(left, text=__version__, text_color=theme.MUTED_FG,
                     font=ctk.CTkFont(size=theme.SIZE_CAPTION)
                     ).pack(side="left", padx=(theme.SPACE_S, 0), pady=(8, 0))

        # The keyring path was the loudest thing on screen and the least
        # important. It keeps only its tail, at caption size.
        middle = ctk.CTkFrame(header, fg_color="transparent")
        middle.grid(row=0, column=1, sticky="w")
        ctk.CTkButton(middle, text=self._short_keyring_path(), height=26,
                      fg_color="transparent", text_color=theme.MUTED_FG,
                      hover_color=theme.NEUTRAL_BG, anchor="w",
                      font=ctk.CTkFont(size=theme.SIZE_CAPTION),
                      command=self._open_keyring_dir).pack(side="left")

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.grid(row=0, column=2, sticky="e",
                   padx=(theme.SPACE_M, theme.SPACE_L), pady=theme.SPACE_M)

        self._lock_button = ctk.CTkButton(
            right, text="No unlocked keys", height=30, width=200,
            fg_color="transparent", border_width=1, border_color=theme.BORDER,
            font=ctk.CTkFont(size=theme.SIZE_CAPTION), command=self._lock_all)
        self._lock_button.pack(side="left", padx=(0, theme.SPACE_S))

        # CTkOptionMenu refuses a transparent fill, so it recedes by tone instead.
        appearance = ctk.CTkOptionMenu(
            right, values=list(APPEARANCE_MODES), width=104, height=30,
            fg_color=theme.NEUTRAL_BG, button_color=theme.NEUTRAL_BG,
            button_hover_color=theme.CARD_BG, text_color=theme.TEXT_SECONDARY,
            font=ctk.CTkFont(size=theme.SIZE_CAPTION),
            command=self._set_appearance)
        appearance.set(self._settings.get("appearance", "System"))
        appearance.pack(side="left")

    def _short_keyring_path(self) -> str:
        """Enough of the path to recognise it, not enough to dominate."""
        parts = os.path.normpath(self.keyring.directory).split(os.sep)
        tail = os.sep.join(parts[-2:]) if len(parts) > 2 else self.keyring.directory
        return "…%s%s" % (os.sep, tail) if len(parts) > 2 else tail

    def _build_tabs(self) -> None:
        self._tabs = ctk.CTkTabview(self, anchor="w", fg_color="transparent")
        self._tabs.grid(row=1, column=0, sticky="nsew",
                        padx=theme.SPACE_L, pady=(0, theme.SPACE_S))

        # CTkTabview offers no public handle on its selector, and at the default
        # size it reads as a widget rather than as the app's navigation.
        try:
            self._tabs._segmented_button.configure(
                height=36, font=ctk.CTkFont(size=theme.SIZE_BODY, weight="bold"))
        except Exception:
            pass

        self.panels = {}
        for name, factory in (("Identities", IdentitiesPanel),
                              ("Encrypt", EncryptPanel),
                              ("Decrypt", DecryptPanel),
                              ("Sign", SignPanel)):
            frame = self._tabs.add(name)
            panel = factory(frame, self)
            panel.pack(fill="both", expand=True)
            self.panels[name] = panel

        # A settings file written by an older build can name a tab that no
        # longer exists; fall back rather than failing to start.
        saved_tab = self._settings.get("tab")
        self._tabs.set(saved_tab if saved_tab in self.panels else "Identities")

    def _build_status(self) -> None:
        self.status = StatusBar(self)
        self.status.grid(row=2, column=0, sticky="ew", padx=theme.PAD,
                         pady=(theme.PAD_S, theme.PAD_S))

    # ------------------------------------------------------------- operations

    def run(self, job: Callable, on_done: Callable, error_title: str,
            on_fail: Optional[Callable] = None, progress: bool = False) -> None:
        """Run ``job(report)`` in the background and report back to the UI."""
        if self.tasks.busy:
            self.status.message("Another operation is already running.", "warn")
            return
        self.touch()
        if progress:
            self.status.progress(0.0)

        def success(result):
            self.status.progress(None)
            on_done(result)

        def failure(exc, tb):
            self.status.progress(None)
            if isinstance(exc, CrsysError):
                message = str(exc)
            else:
                message = "%s: %s" % (type(exc).__name__, exc)
                # The user gets a dialog; whoever is running this from a
                # terminal gets the traceback. An unexpected exception
                # type here means a bug, and a bug should leave evidence.
                print(tb, file=sys.stderr)  # noqa: T201
            self.status.message(error_title, "error")
            if on_fail is not None:
                on_fail(message)
            else:
                dialogs.show_error(self, error_title, message)

        self.tasks.submit(job, success, failure,
                          on_progress=self.status.progress if progress else None)

    def ask_unlock(self, name: str) -> Tuple[bool, Optional[bytes]]:
        """Get the passphrase if one is needed. Returns ``(proceed, passphrase)``."""
        if self.keyring.is_unlocked(name):
            return True, None
        identity = self.keyring.get(name)
        if identity is None or not identity.has_private:
            dialogs.show_error(self, "Key unavailable",
                               'The keyring has no private key named "%s".' % name)
            return False, None
        if not identity.encrypted:
            return True, None
        value = dialogs.ask_passphrase(
            self, 'Unlock "%s"' % name,
            'Enter the passphrase for private key "%s".' % name)
        if value is None:
            return False, None
        return True, value.encode("utf-8")

    def keypair(self, name: str, passphrase: Optional[bytes]):
        """Called from the worker thread: use the cache or derive the key."""
        cached = self.keyring.cached(name)
        if cached is not None:
            return cached
        return self.keyring.unlock(name, passphrase)

    def refresh_identities(self) -> None:
        identities = self.keyring.scan()
        for panel in self.panels.values():
            panel.on_identities_changed(identities)

        unlocked = self.keyring.unlocked_names()
        if unlocked:
            self._lock_button.configure(
                text="%d key%s unlocked — Lock" % (len(unlocked),
                                                   "s" if len(unlocked) > 1 else ""),
                state="normal", text_color=theme.WARN_FG)
        else:
            self._lock_button.configure(text="No unlocked keys",
                                        state="disabled", text_color=theme.MUTED_FG)

    # ------------------------------------------------------------------- misc

    def touch(self) -> None:
        self._last_activity = time.monotonic()

    def _check_autolock(self) -> None:
        idle = time.monotonic() - self._last_activity
        if idle > AUTOLOCK_SECONDS and self.keyring.unlocked_names():
            count = self.keyring.lock_all()
            self.status.message(
                "Idle: %d keys removed from memory." % count, "warn")
            self.refresh_identities()
        self._autolock_id = self.after(30000, self._check_autolock)

    def _lock_all(self) -> None:
        count = self.keyring.lock_all()
        self.status.message("%d keys removed from memory." % count)
        self.refresh_identities()

    def _set_appearance(self, mode: str) -> None:
        ctk.set_appearance_mode(mode)
        self._settings["appearance"] = mode

    def _open_keyring_dir(self) -> None:
        path = self.keyring.directory
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606
            # Suppressed on the next line: `path` is the keyring directory -- either the
            # default or what the user passed on their own command line. Nothing
            # from a container, a filename or a peer reaches it, there is no
            # shell, and the bare program name is the only portable form (there
            # is no canonical location for xdg-open).
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])  # noqa: S603, S607
            else:
                subprocess.Popen(["xdg-open", path])  # noqa: S603, S607
        except Exception as exc:
            dialogs.show_error(self, "Cannot open the folder", str(exc))

    # --------------------------------------------------------------- settings

    def _settings_path(self) -> str:
        return os.path.join(self.keyring.directory, SETTINGS_FILE)

    def _load_settings(self) -> dict:
        try:
            with open(self._settings_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_settings(self) -> None:
        self._settings["geometry"] = self.geometry()
        self._settings["tab"] = self._tabs.get()
        try:
            with open(self._settings_path(), "w", encoding="utf-8") as fh:
                json.dump(self._settings, fh, indent=2)
        except OSError:
            pass

    def _on_close(self) -> None:
        self._save_settings()
        self.keyring.lock_all()  # never leave private keys behind in memory
        self.destroy()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    keyring_dir = None
    if argv and argv[0] in ("-k", "--keyring") and len(argv) > 1:
        keyring_dir = argv[1]
    elif argv and not argv[0].startswith("-"):
        keyring_dir = argv[0]

    try:
        app = CrsysApp(keyring_dir)
    except Exception:
        traceback.print_exc()
        return 1
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
