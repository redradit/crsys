"""GUI tests: the panels are driven from code, with no human involved.

Tk really runs (with the window hidden) and the event loop is pumped by hand
until background operations finish. Modal windows are replaced by functions that
answer on the user's behalf.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest

from _ctx import CheapKdf

from crsys import KeyPair


# CI runners are shared and run this matrix fifteen ways at once, so wall-clock
# budgets have to be generous. The tests do not depend on the duration.
PUMP_TIMEOUT = 60.0


def _pump(app, until=None, timeout: float = PUMP_TIMEOUT) -> bool:
    """Run the event loop until the condition holds or the timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.update()
        if until() if until is not None else not app.tasks.busy:
            return True
        time.sleep(0.01)
    return False


def _settled(app, produced) -> bool:
    """Idle *and* something actually came out.

    Waiting on ``not app.tasks.busy`` alone is ambiguous: it is equally true
    before a task is submitted and after it finishes. If the panel returned
    early — a validation error, or run() declining because another operation was
    in flight — the wait succeeds instantly and the test then asserts against
    stale widget contents. That is what made two GUI tests fail on CI while
    passing locally.
    """
    return not app.tasks.busy and bool(produced())


def _choose(chooser, name: str) -> None:
    """Select an identity in a CTkOptionMenu by its internal name."""
    for label, mapped in chooser._labels.items():
        if mapped == name:
            chooser.set(label)
            return
    raise AssertionError("identity %r missing from the menu (%r)"
                         % (name, list(chooser._labels)))


# CustomTkinter keeps global state (appearance and scaling trackers) tied to the
# existing windows: creating and destroying several roots in one process leaves
# it inconsistent and later operations hang. One window for the whole module,
# which is also how the app is used for real.
_ENV = {}


def setUpModule():
    from crsys_gui import dialogs
    from crsys_gui.app import CrsysApp

    _ENV["dialogs"] = dialogs
    _ENV["kdf"] = CheapKdf()
    _ENV["kdf"].__enter__()
    _ENV["tmp"] = tempfile.TemporaryDirectory()
    _ENV["dir"] = _ENV["tmp"].name
    _ENV["originals"] = {
        name: getattr(dialogs, name)
        for name in ("ask_passphrase", "ask_new_identity", "ask_yes_no",
                     "show_error", "show_info", "ask_name", "ask_public_key")
    }

    try:
        app = CrsysApp(_ENV["dir"])
    except Exception as exc:  # pragma: no cover
        _ENV["kdf"].__exit__(None, None, None)
        _ENV["tmp"].cleanup()
        raise unittest.SkipTest("no usable display: %s" % exc)

    app.withdraw()
    app.keyring.create("alice", "Alice", b"pw")
    app.keyring.create("bob", "Bob", b"pw")
    app.refresh_identities()
    app.update()
    _ENV["app"] = app


def tearDownModule():
    dialogs = _ENV.get("dialogs")
    if dialogs is not None:
        for name, original in _ENV["originals"].items():
            setattr(dialogs, name, original)
    app = _ENV.get("app")
    if app is not None:
        app.keyring.lock_all()
        app.destroy()
    if "kdf" in _ENV:
        _ENV["kdf"].__exit__(None, None, None)
    if "tmp" in _ENV:
        _ENV["tmp"].cleanup()


class GuiTestCase(unittest.TestCase):
    """Base class: restores a known environment before every test."""

    def setUp(self):
        self.app = _ENV["app"]
        self.dialogs = _ENV["dialogs"]
        self.dir = _ENV["dir"]
        self.errors = []

        # Automatic answers standing in for the modal windows.
        self.dialogs.ask_passphrase = lambda *a, **k: "pw"
        self.dialogs.ask_yes_no = lambda *a, **k: True
        self.dialogs.ask_new_identity = lambda *a, **k: None
        self.dialogs.ask_public_key = lambda *a, **k: None
        self.dialogs.ask_name = lambda *a, **k: None
        self.dialogs.show_info = lambda *a, **k: None
        self.dialogs.show_error = lambda parent, title, message: self.errors.append(
            (title, message))

        for name in ("alice", "bob"):
            if not self.app.keyring.is_unlocked(name):
                self.app.keyring.unlock(name, b"pw")
        self.app.touch()
        self.app.refresh_identities()
        self.app.update()

    # ------------------------------------------------------------------ tools

    @property
    def identities(self):
        return self.app.panels["Identities"]

    @property
    def encrypt(self):
        return self.app.panels["Encrypt"]

    @property
    def decrypt(self):
        return self.app.panels["Decrypt"]

    @property
    def sign(self):
        return self.app.panels["Sign"]

    def banner_text(self, banner) -> str:
        return banner._label.cget("text")

    def await_result(self, produced, message="the operation produced nothing"):
        """Wait for the worker to finish *and* for a visible result to appear."""
        self.assertTrue(_pump(self.app, lambda: _settled(self.app, produced)), message)


class TestStartup(GuiTestCase):
    def test_window_and_panels(self):
        self.assertEqual(sorted(self.app.panels),
                         sorted(["Identities", "Encrypt", "Decrypt", "Sign"]))
        self.assertTrue(self.app.title().startswith("CRSYS"))

    def test_identities_propagate_to_panels(self):
        names = {i.name for i in self.app.keyring.scan()}
        self.assertEqual(names, {"alice", "bob"})
        self.assertEqual(set(self.encrypt._recipients._vars), {"alice", "bob"})
        self.assertEqual(set(self.decrypt._key._labels.values()), {"alice", "bob"})

    def test_keyring_on_disk(self):
        for name in ("alice", "bob"):
            for ext in (".key", ".pub"):
                self.assertTrue(os.path.exists(os.path.join(self.dir, name + ext)))

    def test_keys_unlocked_after_creation(self):
        self.assertEqual(self.app.keyring.unlocked_names(), ["alice", "bob"])
        self.assertIn("unlocked", self.app._lock_button.cget("text"))


class TestIdentitiesPanel(GuiTestCase):
    def test_generate_from_dialog(self):
        self.dialogs.ask_new_identity = lambda *a, **k: {
            "name": "carol", "comment": "Carol", "passphrase": "pw"}
        self.identities._generate()
        self.await_result(lambda: self.app.keyring.get("carol"),
                          "carol was never created")
        self.assertIn("carol", {i.name for i in self.app.keyring.scan()})
        self.assertEqual(self.identities._selected, "carol")

        self.identities._selected = "carol"
        self.identities._delete()
        self.assertNotIn("carol", {i.name for i in self.app.keyring.scan()})

    def test_cancelling_creates_nothing(self):
        before = {i.name for i in self.app.keyring.scan()}
        self.dialogs.ask_new_identity = lambda *a, **k: None
        self.identities._generate()
        self.assertEqual({i.name for i in self.app.keyring.scan()}, before)

    def test_duplicate_name_rejected(self):
        from crsys.errors import CrsysError

        with self.assertRaises(CrsysError):
            self.app.keyring.create("alice", "", b"pw")

    def test_lock_and_unlock(self):
        self.identities._selected = "alice"
        self.app.keyring.lock("alice")
        self.app.refresh_identities()
        self.assertFalse(self.app.keyring.is_unlocked("alice"))

        self.identities._toggle_lock()  # ask_passphrase answers "pw"
        self.await_result(lambda: self.app.keyring.is_unlocked("alice"),
                          "alice never unlocked")
        self.assertTrue(self.app.keyring.is_unlocked("alice"))

    def test_import_public(self):
        stranger = KeyPair.generate(comment="Dave")
        self.dialogs.ask_public_key = lambda *a, **k: {
            "name": "dave", "source": stranger.public_key.to_compact()}
        self.identities._import_public()
        identity = self.app.keyring.get("dave")
        self.assertIsNotNone(identity)
        self.assertEqual(identity.public_key, stranger.public_key)
        self.assertFalse(identity.has_private)

        self.identities._selected = "dave"
        self.identities._delete()
        self.assertIsNone(self.app.keyring.get("dave"))

    def test_detail_shows_compact_form(self):
        self.identities._select("bob")
        compact = self.identities._compact.get()
        self.assertTrue(compact.startswith("crsys1"))
        self.assertEqual(compact, self.app.keyring.public_key("bob").to_compact())


class TestTextEncryption(GuiTestCase):
    def _encrypt_text(self, text, recipients, signer=None):
        panel = self.encrypt
        panel._mode.set("Text")
        panel._switch_mode("Text")
        panel._input_text.set(text)
        panel._output_text.set("")          # never assert against stale output
        panel._banner.clear()
        panel._recipients.select(recipients)
        if signer:
            _choose(panel._signer, signer)
        else:
            panel._signer.set(panel._signer.NONE_LABEL)
        panel._encrypt()
        produced = lambda: panel._output_text.get() or self.banner_text(panel._banner)
        self.assertTrue(_pump(self.app, lambda: _settled(self.app, produced)),
                        "encryption produced nothing: banner=%r"
                        % self.banner_text(panel._banner))
        return panel._output_text.get()

    def _decrypt_text(self, sealed, key, expected=None):
        panel = self.decrypt
        panel._mode.set("Text")
        panel._switch_mode("Text")
        panel._input_text.set(sealed)
        panel._output_text.set("")
        panel._banner.clear()
        _choose(panel._key, key)
        if expected:
            _choose(panel._expected, expected)
        else:
            panel._expected.set(panel._expected.NONE_LABEL)
        panel._decrypt()
        produced = lambda: panel._output_text.get() or self.banner_text(panel._banner)
        self.assertTrue(_pump(self.app, lambda: _settled(self.app, produced)),
                        "decryption produced nothing")
        return panel._output_text.get(), self.banner_text(panel._banner)

    def test_full_signed_cycle(self):
        sealed = self._encrypt_text("hi Bob, everything is ready", ["bob"],
                                    signer="alice")
        self.assertTrue(sealed.startswith("-----BEGIN CRSYS MESSAGE-----"))

        plaintext, banner = self._decrypt_text(sealed, "bob", expected="alice")
        self.assertEqual(plaintext, "hi Bob, everything is ready")
        self.assertIn("Valid signature", banner)
        self.assertIn("alice", banner)

    def test_unsigned_warns(self):
        sealed = self._encrypt_text("anonymous message", ["bob"])
        plaintext, banner = self._decrypt_text(sealed, "bob")
        self.assertEqual(plaintext, "anonymous message")
        self.assertIn("NOT signed", banner)

    def test_expected_signer_differs(self):
        sealed = self._encrypt_text("from bob", ["bob"], signer="bob")
        _, banner = self._decrypt_text(sealed, "bob", expected="alice")
        self.assertIn("expected", banner.lower())

    def test_wrong_recipient(self):
        sealed = self._encrypt_text("for bob only", ["bob"], signer="alice")
        _, banner = self._decrypt_text(sealed, "alice")
        self.assertIn("not for you", banner)

    def test_two_recipients(self):
        sealed = self._encrypt_text("for both", ["alice", "bob"], signer="alice")
        for key in ("alice", "bob"):
            plaintext, _ = self._decrypt_text(sealed, key)
            self.assertEqual(plaintext, "for both")

    def test_tampered_text(self):
        sealed = self._encrypt_text("intact", ["bob"])
        lines = sealed.splitlines()
        lines[1] = ("A" if lines[1][0] != "A" else "B") + lines[1][1:]
        _, banner = self._decrypt_text("\n".join(lines), "bob")
        self.assertTrue(banner)
        self.assertNotIn("Valid signature", banner)

    def test_no_recipients(self):
        panel = self.encrypt
        panel._mode.set("Text")
        panel._switch_mode("Text")
        panel._input_text.set("something")
        panel._recipients.select([])
        panel._encrypt()
        self.assertIn("at least one recipient", self.banner_text(panel._banner))

    def test_empty_text(self):
        panel = self.encrypt
        panel._mode.set("Text")
        panel._switch_mode("Text")
        panel._input_text.set("")
        panel._recipients.select(["bob"])
        panel._encrypt()
        self.assertIn("Write a message", self.banner_text(panel._banner))

    def test_text_mode_forces_armor(self):
        self.encrypt._switch_mode("Text")
        self.assertTrue(self.encrypt._armor.get())
        self.assertEqual(str(self.encrypt._armor.cget("state")), "disabled")
        self.encrypt._switch_mode("File")
        self.assertEqual(str(self.encrypt._armor.cget("state")), "normal")


class TestFileEncryption(GuiTestCase):
    def test_full_file_cycle(self):
        src = os.path.join(self.dir, "document.txt")
        enc = os.path.join(self.dir, "document.crsys")
        dec = os.path.join(self.dir, "document.out")
        content = ("test line\n" * 4000).encode("utf-8")
        with open(src, "wb") as fh:
            fh.write(content)

        panel = self.encrypt
        panel._mode.set("File")
        panel._switch_mode("File")
        panel._input_file.set(src)
        panel._output_file.set(enc)
        panel._recipients.select(["bob"])
        _choose(panel._signer, "alice")
        panel._banner.clear()
        panel._encrypt()
        self.await_result(lambda: self.banner_text(panel._banner))
        self.assertTrue(os.path.exists(enc), self.banner_text(panel._banner))
        self.assertIn("Done", self.banner_text(panel._banner))

        panel = self.decrypt
        panel._mode.set("File")
        panel._switch_mode("File")
        panel._input_file.set(enc)
        panel._output_file.set(dec)
        _choose(panel._key, "bob")
        _choose(panel._expected, "alice")
        panel._banner.clear()
        panel._decrypt()
        self.await_result(lambda: self.banner_text(panel._banner))
        with open(dec, "rb") as fh:
            self.assertEqual(fh.read(), content)
        self.assertIn("Valid signature", self.banner_text(panel._banner))

    def test_missing_file(self):
        panel = self.encrypt
        panel._mode.set("File")
        panel._switch_mode("File")
        panel._input_file.set(os.path.join(self.dir, "does-not-exist.bin"))
        panel._output_file.set(os.path.join(self.dir, "x.crsys"))
        panel._recipients.select(["bob"])
        panel._encrypt()
        self.assertIn("Choose a file", self.banner_text(panel._banner))

    def test_inspection_without_keys(self):
        src = os.path.join(self.dir, "inspect.txt")
        enc = os.path.join(self.dir, "inspect.crsys")
        with open(src, "wb") as fh:
            fh.write(b"content")

        panel = self.encrypt
        panel._mode.set("File")
        panel._switch_mode("File")
        panel._input_file.set(src)
        panel._output_file.set(enc)
        panel._recipients.select(["bob"])
        _choose(panel._signer, "alice")
        panel._banner.clear()
        panel._encrypt()
        self.await_result(lambda: self.banner_text(panel._banner))

        panel = self.decrypt
        panel._mode.set("File")
        panel._switch_mode("File")
        panel._input_file.set(enc)
        panel._inspect()
        text = self.banner_text(panel._banner)
        self.assertIn("signed", text)
        self.assertIn("bob", text)

    def test_inspecting_an_arbitrary_file(self):
        path = os.path.join(self.dir, "not-crsys.bin")
        with open(path, "wb") as fh:
            fh.write(b"I am not a container")
        panel = self.decrypt
        panel._mode.set("File")
        panel._switch_mode("File")
        panel._input_file.set(path)
        panel._inspect()
        self.assertIn("not a readable crsys container",
                      self.banner_text(panel._banner).lower())


class TestSignPanel(GuiTestCase):
    def test_sign_and_verify(self):
        path = os.path.join(self.dir, "to-sign.txt")
        sig = os.path.join(self.dir, "to-sign.txt.sig")
        with open(path, "wb") as fh:
            fh.write(b"public but authentic content")

        panel = self.sign
        panel._sign_input.set(path)
        panel._sign_output.set(sig)
        _choose(panel._signer, "alice")
        panel._sign_banner.clear()
        panel._sign()
        self.await_result(lambda: self.banner_text(panel._sign_banner))
        self.assertTrue(os.path.exists(sig), self.banner_text(panel._sign_banner))

        panel._verify_input.set(path)
        panel._verify_sig.set(sig)
        panel._verify_text.set("")
        _choose(panel._expected, "alice")
        panel._verify_banner.clear()
        panel._verify()
        self.await_result(lambda: self.banner_text(panel._verify_banner))
        self.assertIn("VALID", self.banner_text(panel._verify_banner))

    def test_file_modified_after_signing(self):
        path = os.path.join(self.dir, "modified.txt")
        sig = os.path.join(self.dir, "modified.sig")
        with open(path, "wb") as fh:
            fh.write(b"version 1")

        panel = self.sign
        panel._sign_input.set(path)
        panel._sign_output.set(sig)
        _choose(panel._signer, "alice")
        panel._sign_banner.clear()
        panel._sign()
        self.await_result(lambda: self.banner_text(panel._sign_banner))

        with open(path, "ab") as fh:
            fh.write(b" altered")

        panel._verify_input.set(path)
        panel._verify_sig.set(sig)
        panel._verify_text.set("")
        panel._expected.set(panel._expected.NONE_LABEL)
        panel._verify_banner.clear()
        panel._verify()
        self.await_result(lambda: self.banner_text(panel._verify_banner))
        self.assertIn("invalid", self.banner_text(panel._verify_banner).lower())


class TestInterfaceSecurity(GuiTestCase):
    def test_autolock_on_idle(self):
        self.app.keyring.unlock("alice", b"pw")
        self.assertTrue(self.app.keyring.unlocked_names())
        self.app._last_activity = time.monotonic() - 3600
        self.app._check_autolock()
        self.assertEqual(self.app.keyring.unlocked_names(), [])
        self.app.keyring.unlock("alice", b"pw")
        self.app.keyring.unlock("bob", b"pw")

    def test_cancelling_the_passphrase_stops(self):
        self.app.keyring.lock("bob")
        self.dialogs.ask_passphrase = lambda *a, **k: None
        try:
            proceed, passphrase = self.app.ask_unlock("bob")
        finally:
            self.dialogs.ask_passphrase = lambda *a, **k: "pw"
        self.assertFalse(proceed)
        self.assertIsNone(passphrase)
        self.app.keyring.unlock("bob", b"pw")

    def test_dangerous_identity_names_rejected(self):
        from crsys.errors import CrsysError

        for name in ("../escape", "with/slash", "with\\backslash", "", ".hidden",
                     "a" * 200):
            with self.subTest(name=name), self.assertRaises(CrsysError):
                self.app.keyring.create(name, "", b"pw")

    def test_closing_locks_everything(self):
        """Closing must not leave private keys in memory."""
        self.assertTrue(self.app.keyring.unlocked_names())
        self.app._save_settings()
        self.app.keyring.lock_all()
        self.assertEqual(self.app.keyring.unlocked_names(), [])
        self.app.keyring.unlock("alice", b"pw")
        self.app.keyring.unlock("bob", b"pw")

    def test_settings_persist(self):
        import json

        self.app._save_settings()
        with open(os.path.join(self.dir, "gui.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("geometry", data)
        self.assertIn("tab", data)

    def test_stale_settings_do_not_break_startup(self):
        """A settings file from an older build must not prevent launching."""
        from crsys_gui.app import APPEARANCE_MODES

        stale = {"tab": "NoSuchTab", "appearance": "Italiano", "geometry": "900x600"}
        self.assertNotIn(stale["tab"], self.app.panels)
        self.assertNotIn(stale["appearance"], APPEARANCE_MODES)

        # Same normalisation the constructor applies, exercised without a
        # second Tk root (CustomTkinter does not tolerate one per test).
        tab = stale["tab"] if stale["tab"] in self.app.panels else "Identities"
        appearance = (stale["appearance"] if stale["appearance"] in APPEARANCE_MODES
                      else "System")
        self.assertEqual(tab, "Identities")
        self.assertEqual(appearance, "System")
        self.app._tabs.set(tab)


if __name__ == "__main__":
    unittest.main()
