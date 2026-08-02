"""GUI tests: the panels are driven from code, with no human involved.

Tk really runs (with the window hidden) and the event loop is pumped by hand
until background operations finish. Modal windows are replaced by functions that
answer on the user's behalf.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import time
import unittest

from _ctx import CheapKdf

from crsys import KeyPair, PublicKey
from crsys.errors import PassphraseError


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
        self.assertEqual(set(self.encrypt._recipients._boxes), {"alice", "bob"})
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

    def test_import_menu_entries_reach_their_handlers(self):
        """Regression: choosing from the Import menu did nothing at all.

        The menu was a hand-rolled popup that closed itself on <FocusOut>.
        Pressing an entry moved focus, so it destroyed itself on mouse-down and
        the button was gone before its command could run. Every other path was
        tested by calling _import_public and _import_private directly, which
        skipped the menu entirely and left the only broken part uncovered.

        The menu is built here but never posted: tk_popup would block.
        """
        menu = self.identities.build_import_menu()
        try:
            labels = [menu.entrycget(i, "label") for i in range(menu.index("end") + 1)]
            self.assertEqual([label.strip() for label in labels],
                             ["Public key…", "Private key…"])

            calls = []
            self.dialogs.ask_public_key = lambda *a, **k: calls.append("public")
            menu.invoke(0)
            self.assertEqual(calls, ["public"],
                             "the Public key entry did not reach its handler")

            from crsys_gui import tab_identities as ti

            real = ti.filedialog.askopenfilename
            ti.filedialog.askopenfilename = lambda *a, **k: calls.append("private") or ""
            try:
                menu.invoke(1)
            finally:
                ti.filedialog.askopenfilename = real
            self.assertEqual(calls, ["public", "private"],
                             "the Private key entry did not reach its handler")
        finally:
            menu.destroy()

    def test_import_button_anchors_the_menu(self):
        """The menu is placed under the button, not at a hardcoded offset."""
        self.assertTrue(self.identities._import_button.winfo_exists())

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
                        "encryption never finished: banner=%r"
                        % self.banner_text(panel._banner))
        sealed = panel._output_text.get()
        # The wait is satisfied by a banner as well as by output, so a *failed*
        # encryption also ends it. Without this check the test would carry an
        # empty string into the decrypt step and report the mismatch there,
        # naming the symptom instead of the cause.
        self.assertTrue(
            sealed.startswith("-----BEGIN CRSYS MESSAGE-----"),
            "encryption failed: banner=%r, output=%r"
            % (self.banner_text(panel._banner), sealed[:120]))
        return sealed

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
                        "decryption never finished: busy=%s, banner=%r, status=%r"
                        % (self.app.tasks.busy, self.banner_text(panel._banner),
                           self.app.status._label.cget("text")))
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


class TestDialogValidation(GuiTestCase):
    """The modal dialogs' validation logic, exercised without a human.

    Everywhere else these dialogs are replaced by stubs that answer on the
    user's behalf, which left their validation entirely unexecuted -- and it is
    not cosmetic. It is what stops an identity name from escaping the keyring
    folder, and what stops a mistyped passphrase from locking someone out of
    their own private key. Here the classes are driven directly: fill the
    widgets, call the accept handler, inspect the outcome.
    """

    def _run(self, dialog_cls, args, action):
        """Build a dialog, drive it, destroy it. Never calls show()."""
        dialog = dialog_cls(self.app, *args)
        try:
            self.app.update()
            action(dialog)
            return dialog.result, dialog._error.cget("text")
        finally:
            dialog.destroy()
            self.app.update()

    # ------------------------------------------------------------ passphrase

    def _passphrase(self, action, confirm=False):
        from crsys_gui.dialogs import PassphraseDialog

        return self._run(PassphraseDialog,
                         (self.app, "Title", "Message", confirm)[1:], action)

    def test_passphrase_accepted(self):
        def fill(d):
            d._entry.insert(0, "correct horse")
            d._ok()

        result, error = self._passphrase(fill)
        self.assertEqual(result, "correct horse")
        self.assertEqual(error, "")

    def test_passphrase_rejects_empty(self):
        result, error = self._passphrase(lambda d: d._ok())
        self.assertIsNone(result)
        self.assertIn("cannot be empty", error)

    def test_passphrase_confirmation_must_match(self):
        def mismatch(d):
            d._entry.insert(0, "one")
            d._entry2.insert(0, "two")
            d._ok()

        result, error = self._passphrase(mismatch, confirm=True)
        self.assertIsNone(result)
        self.assertIn("do not match", error)

    def test_passphrase_confirmation_matching(self):
        def matching(d):
            d._entry.insert(0, "same")
            d._entry2.insert(0, "same")
            d._ok()

        result, _ = self._passphrase(matching, confirm=True)
        self.assertEqual(result, "same")

    def test_passphrase_cancel(self):
        def cancel(d):
            d._entry.insert(0, "typed but abandoned")
            d._cancel()

        result, _ = self._passphrase(cancel)
        self.assertIsNone(result)

    # -------------------------------------------------------- new identity

    def _new_identity(self, action, existing=()):
        from crsys_gui.dialogs import NewIdentityDialog

        return self._run(NewIdentityDialog, (existing,), action)

    def test_new_identity_accepted(self):
        def fill(d):
            d._name.insert(0, "dave")
            d._comment.insert(0, "Dave <dave@example.com>")
            d._pass1.insert(0, "pw")
            d._pass2.insert(0, "pw")
            d._ok()

        result, error = self._new_identity(fill)
        self.assertEqual(error, "")
        self.assertEqual(result, {"name": "dave",
                                  "comment": "Dave <dave@example.com>",
                                  "passphrase": "pw"})

    def test_new_identity_rejects_dangerous_names(self):
        """The same names the keyring refuses must never get that far."""
        for name in ("../escape", "with/slash", "with\\backslash", "", ".hidden",
                     "a" * 200, "  "):
            def fill(d, n=name):
                d._name.insert(0, n)
                d._pass1.insert(0, "pw")
                d._pass2.insert(0, "pw")
                d._ok()

            with self.subTest(name=name):
                result, error = self._new_identity(fill)
                self.assertIsNone(result)
                self.assertIn("Invalid name", error)

    def test_new_identity_rejects_duplicate(self):
        def fill(d):
            d._name.insert(0, "alice")
            d._pass1.insert(0, "pw")
            d._pass2.insert(0, "pw")
            d._ok()

        result, error = self._new_identity(fill, existing=("alice", "bob"))
        self.assertIsNone(result)
        self.assertIn("already exists", error)

    def test_new_identity_rejects_mismatched_passphrase(self):
        def fill(d):
            d._name.insert(0, "dave")
            d._pass1.insert(0, "one")
            d._pass2.insert(0, "two")
            d._ok()

        result, error = self._new_identity(fill)
        self.assertIsNone(result)
        self.assertIn("do not match", error)

    def test_new_identity_rejects_empty_passphrase(self):
        def fill(d):
            d._name.insert(0, "dave")
            d._ok()

        result, error = self._new_identity(fill)
        self.assertIsNone(result)
        self.assertIn("Enter a passphrase", error)

    def test_new_identity_without_passphrase(self):
        """Opting out must disable the fields and yield a None passphrase."""
        captured = {}

        def fill(d):
            d._name.insert(0, "dave")
            d._none.select()
            d._toggle_passphrase()
            captured["state"] = str(d._pass1.cget("state"))
            d._ok()

        result, _ = self._new_identity(fill)
        self.assertEqual(captured["state"], "disabled")
        self.assertEqual(result, {"name": "dave", "comment": "",
                                  "passphrase": None})

    # ---------------------------------------------------------------- name

    def _name_dialog(self, action, existing=()):
        from crsys_gui.dialogs import NameDialog

        return self._run(NameDialog, ("Title", "Message", existing), action)

    def test_name_dialog_accepts_and_rejects(self):
        def good(d):
            d._entry.insert(0, "carol")
            d._ok()

        self.assertEqual(self._name_dialog(good)[0], "carol")

        def bad(d):
            d._entry.insert(0, "../escape")
            d._ok()

        result, error = self._name_dialog(bad)
        self.assertIsNone(result)
        self.assertIn("Invalid name", error)

        def duplicate(d):
            d._entry.insert(0, "bob")
            d._ok()

        result, error = self._name_dialog(duplicate, existing=("bob",))
        self.assertIsNone(result)
        self.assertIn("already used", error)

    # ------------------------------------------------------- import public

    def _import_public(self, action, existing=()):
        from crsys_gui.dialogs import ImportPublicDialog

        return self._run(ImportPublicDialog, (existing,), action)

    def test_import_public_accepts_a_compact_key(self):
        compact = KeyPair.generate().public_key.to_compact()

        def fill(d):
            d._name.insert(0, "dave")
            d._text.insert("0.0", compact)
            d._ok()

        result, error = self._import_public(fill)
        self.assertEqual(error, "")
        self.assertEqual(result, {"name": "dave", "source": compact})

    def test_import_public_accepts_an_armored_block(self):
        armored = KeyPair.generate().public_key.to_text()

        def fill(d):
            d._name.insert(0, "dave")
            d._text.insert("0.0", armored)
            d._ok()

        result, _ = self._import_public(fill)
        self.assertIsNotNone(result)

    def test_import_public_rejects_junk(self):
        for junk in ("not a key", "crsys1zzzz", "-----BEGIN CRSYS PUBLIC KEY-----"):
            def fill(d, j=junk):
                d._name.insert(0, "dave")
                d._text.insert("0.0", j)
                d._ok()

            with self.subTest(junk=junk[:20]):
                result, error = self._import_public(fill)
                self.assertIsNone(result)
                self.assertIn("Invalid key", error)

    # There is deliberately no NUL byte case here, and it should not be added
    # back. Pushing a NUL through a Tk text widget tests the toolkit, not this
    # code: whether it survives depends on the bundled Tcl version, and on macOS
    # it left the widget in a state that dragged the rest of the class from 19
    # seconds to over four minutes. PublicKey.parse's handling of NUL is real
    # behaviour and is tested directly, without a GUI, in
    # test_keys.test_parse_rejects_junk_as_format_error.

    def test_import_public_rejects_empty_text(self):
        def fill(d):
            d._name.insert(0, "dave")
            d._ok()

        result, error = self._import_public(fill)
        self.assertIsNone(result)
        self.assertIn("Paste a public key", error)

    def test_import_public_rejects_bad_name(self):
        compact = KeyPair.generate().public_key.to_compact()

        def fill(d):
            d._name.insert(0, "../escape")
            d._text.insert("0.0", compact)
            d._ok()

        result, error = self._import_public(fill)
        self.assertIsNone(result)
        self.assertIn("Invalid name", error)


@contextlib.contextmanager
def _file_dialogs(open_path="", save_path=""):
    """Answer the native file choosers, which no test can click."""
    from crsys_gui import tab_identities as ti

    real_open = ti.filedialog.askopenfilename
    real_save = ti.filedialog.asksaveasfilename
    ti.filedialog.askopenfilename = lambda *a, **k: open_path
    ti.filedialog.asksaveasfilename = lambda *a, **k: save_path
    try:
        yield
    finally:
        ti.filedialog.askopenfilename = real_open
        ti.filedialog.asksaveasfilename = real_save


class TestIdentityPanelActions(GuiTestCase):
    """The actions that touch private key material on disk.

    These were the least covered paths in the interface and the ones with the
    least forgiving failure mode: importing, re-encrypting and deleting private
    keys destroys material that cannot be recovered from anywhere else. Each
    test cleans up whatever it creates, because later classes assert on the
    exact contents of the keyring.
    """

    def _external_key(self, name, passphrase=b"pw"):
        """A key file sitting outside the keyring, ready to be imported."""
        outside = os.path.join(self.dir, "external")
        os.makedirs(outside, exist_ok=True)
        path = os.path.join(outside, name + ".key")
        keypair = KeyPair.generate(comment="external")
        keypair.save(path, passphrase)
        return path, keypair

    def _discard(self, *names):
        for name in names:
            if self.app.keyring.get(name) is not None:
                self.app.keyring.delete(name)
        self.app.refresh_identities()

    # ------------------------------------------------------- import private

    def test_import_private_key(self):
        path, original = self._external_key("incoming")
        self.dialogs.ask_name = lambda *a, **k: "imported"
        try:
            with _file_dialogs(open_path=path):
                self.identities._import_private()
            self.await_result(lambda: self.app.keyring.get("imported"),
                              "the key was never imported")

            identity = self.app.keyring.get("imported")
            self.assertTrue(identity.has_private)
            self.assertEqual(identity.public_key, original.public_key)
            # The imported copy must open with the passphrase it was made with.
            self.assertEqual(
                self.app.keyring.cached("imported").secret_bytes(),
                original.secret_bytes())
            # And the public half must have been written out alongside it.
            self.assertTrue(os.path.exists(
                os.path.join(self.dir, "imported.pub")))
        finally:
            self._discard("imported")

    def test_import_private_cancelled_at_each_step(self):
        path, _ = self._external_key("cancelled")
        before = {i.name for i in self.app.keyring.scan()}

        # Cancelled at the file chooser.
        with _file_dialogs(open_path=""):
            self.identities._import_private()

        # Cancelled at the name prompt.
        self.dialogs.ask_name = lambda *a, **k: None
        with _file_dialogs(open_path=path):
            self.identities._import_private()

        # Cancelled at the passphrase prompt.
        self.dialogs.ask_name = lambda *a, **k: "abandoned"
        self.dialogs.ask_passphrase = lambda *a, **k: None
        with _file_dialogs(open_path=path):
            self.identities._import_private()

        self.assertEqual({i.name for i in self.app.keyring.scan()}, before)

    def test_import_private_unreadable_file(self):
        junk = os.path.join(self.dir, "external", "broken.key")
        os.makedirs(os.path.dirname(junk), exist_ok=True)
        with open(junk, "wb") as fh:
            fh.write(b"this is not a key file")

        self.dialogs.ask_name = lambda *a, **k: "broken"
        with _file_dialogs(open_path=junk):
            self.identities._import_private()

        self.assertTrue(self.errors, "no error was reported to the user")
        self.assertIn("Unreadable file", self.errors[0][0])
        self.assertIsNone(self.app.keyring.get("broken"))

    # ----------------------------------------------------- change passphrase

    def _passphrase_answers(self, current="pw", new="newpw"):
        """The dialog is asked twice; the second call sets confirm=True."""
        def answer(parent, title, message, confirm=False):
            return new if confirm else current
        self.dialogs.ask_passphrase = answer

    def test_change_passphrase_while_locked(self):
        self.app.keyring.create("rotate", "Rotate", b"pw")
        self.app.keyring.lock("rotate")
        self.app.refresh_identities()
        self.identities._selected = "rotate"
        key_path = self.app.keyring.get("rotate").key_path
        try:
            self._passphrase_answers(current="pw", new="rotated")
            self.identities._change_passphrase()
            self.await_result(
                lambda: "updated" in self.app.status._label.cget("text"))

            with self.assertRaises(PassphraseError):
                KeyPair.load(key_path, b"pw")
            self.assertIsNotNone(KeyPair.load(key_path, b"rotated"))
        finally:
            self._discard("rotate")

    def test_change_passphrase_while_unlocked(self):
        """Unlocked takes the other branch: the cached key is rewritten."""
        self.app.keyring.create("rotate2", "Rotate", b"pw")
        self.app.refresh_identities()
        self.identities._selected = "rotate2"
        identity = self.app.keyring.get("rotate2")
        self.assertTrue(identity.unlocked)
        key_path = identity.key_path
        try:
            self._passphrase_answers(new="rotated2")
            self.identities._change_passphrase()
            self.await_result(
                lambda: "updated" in self.app.status._label.cget("text"))
            self.assertIsNotNone(KeyPair.load(key_path, b"rotated2"))
        finally:
            self._discard("rotate2")

    def test_change_passphrase_cancelled_leaves_the_key_alone(self):
        self.app.keyring.create("keepme", "Keep", b"pw")
        self.app.keyring.lock("keepme")
        self.app.refresh_identities()
        self.identities._selected = "keepme"
        key_path = self.app.keyring.get("keepme").key_path
        try:
            self.dialogs.ask_passphrase = lambda *a, **k: None
            self.identities._change_passphrase()
            self.app.update()
            self.assertIsNotNone(KeyPair.load(key_path, b"pw"))

            # Cancelled at the second prompt, after supplying the current one.
            def only_current(parent, title, message, confirm=False):
                return None if confirm else "pw"
            self.dialogs.ask_passphrase = only_current
            self.identities._change_passphrase()
            self.app.update()
            self.assertIsNotNone(KeyPair.load(key_path, b"pw"))
        finally:
            self._discard("keepme")

    # ------------------------------------------------------- export and copy

    def test_export_public_key(self):
        target = os.path.join(self.dir, "external", "exported.pub")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        self.identities._select("bob")
        with _file_dialogs(save_path=target):
            self.identities._export_public()
        self.assertTrue(os.path.exists(target))
        self.assertEqual(PublicKey.load(target),
                         self.app.keyring.public_key("bob"))

    def test_export_public_cancelled(self):
        self.identities._select("bob")
        with _file_dialogs(save_path=""):
            self.identities._export_public()
        self.assertFalse(self.errors)

    def test_export_public_to_an_unwritable_path(self):
        target = os.path.join(self.dir, "no-such-directory", "x.pub")
        self.identities._select("bob")
        with _file_dialogs(save_path=target):
            self.identities._export_public()
        self.assertTrue(self.errors, "a failed export must tell the user")
        self.assertIn("Export failed", self.errors[0][0])

    def test_copy_compact_form(self):
        self.identities._select("bob")
        self.identities._copy_compact()
        self.app.update()
        self.assertEqual(self.app.clipboard_get(),
                         self.app.keyring.public_key("bob").to_compact())

    # ------------------------------------------------------------- deletion

    def test_delete_refused_when_the_user_says_no(self):
        self.app.keyring.create("doomed", "Doomed", b"pw")
        self.app.refresh_identities()
        self.identities._selected = "doomed"
        try:
            self.dialogs.ask_yes_no = lambda *a, **k: False
            self.identities._delete()
            self.assertIsNotNone(self.app.keyring.get("doomed"))
        finally:
            self.dialogs.ask_yes_no = lambda *a, **k: True
            self._discard("doomed")

    def test_delete_warns_harder_about_a_private_key(self):
        """The confirmation text must say the material is unrecoverable."""
        seen = {}

        def capture(parent, title, message):
            seen["message"] = message
            return False

        self.app.keyring.create("withpriv", "With private", b"pw")
        self.app.keyring.import_public(
            KeyPair.generate().public_key.to_compact(), "publiconly")
        self.app.refresh_identities()
        try:
            self.dialogs.ask_yes_no = capture

            self.identities._selected = "withpriv"
            self.identities._delete()
            self.assertIn("PRIVATE KEY", seen["message"])
            self.assertIn("permanently unreadable", seen["message"])

            self.identities._selected = "publiconly"
            self.identities._delete()
            self.assertNotIn("PRIVATE KEY", seen["message"])
        finally:
            self.dialogs.ask_yes_no = lambda *a, **k: True
            self._discard("withpriv", "publiconly")

    def test_delete_removes_both_files(self):
        self.app.keyring.create("goodbye", "Goodbye", b"pw")
        self.app.refresh_identities()
        self.identities._selected = "goodbye"
        self.identities._delete()
        self.assertIsNone(self.app.keyring.get("goodbye"))
        for ext in (".key", ".pub"):
            self.assertFalse(os.path.exists(
                os.path.join(self.dir, "goodbye" + ext)))
        self.assertNotIn("goodbye", self.app.keyring.unlocked_names())

    # --------------------------------------------------------------- sundry

    def test_lock_all_from_the_panel(self):
        self.app.keyring.unlock("alice", b"pw")
        self.identities._lock_all_keys()
        self.assertEqual(self.app.keyring.unlocked_names(), [])

    def test_actions_are_inert_with_nothing_selected(self):
        """Every handler guards on there being a selection."""
        self.identities._selected = None
        self.identities._toggle_lock()
        self.identities._change_passphrase()
        self.identities._export_public()
        self.identities._copy_compact()
        self.identities._delete()
        self.assertFalse(self.errors)

    def test_import_public_reports_a_bad_key(self):
        self.dialogs.ask_public_key = lambda *a, **k: {
            "name": "bogus", "source": "not a key at all"}
        self.identities._import_public()
        self.assertTrue(self.errors)
        self.assertIn("Import failed", self.errors[0][0])
        self.assertIsNone(self.app.keyring.get("bogus"))

    def test_row_hover_changes_only_unselected_rows(self):
        from crsys_gui.tab_identities import IdentityRow

        rows = [w for w in self.identities._list.winfo_children()
                if isinstance(w, IdentityRow)]
        self.assertTrue(rows, "the identity list rendered no rows")
        unselected = [r for r in rows if not r._selected]
        self.assertTrue(unselected)

        row = unselected[0]
        row._enter()
        hovered = row.cget("fg_color")
        row._leave()
        self.assertEqual(row.cget("fg_color"), "transparent")
        self.assertNotEqual(hovered, "transparent")


class TestAppPlumbing(GuiTestCase):
    """The application's own decision points, not any one panel's.

    ask_unlock is the gate that decides whether a passphrase is demanded at all,
    and keypair() is what the worker thread calls to obtain a private key. Both
    were reached only through the happy path, which never exercised the branches
    that decide *not* to ask.
    """

    def _refuse_to_prompt(self):
        """Install a passphrase dialog that fails the test if it is called."""
        def forbidden(*a, **k):
            raise AssertionError("a passphrase was requested when none was needed")
        self.dialogs.ask_passphrase = forbidden

    # ------------------------------------------------------------ ask_unlock

    def test_unlock_not_asked_when_already_unlocked(self):
        self.assertTrue(self.app.keyring.is_unlocked("alice"))
        self._refuse_to_prompt()
        self.assertEqual(self.app.ask_unlock("alice"), (True, None))

    def test_unlock_not_asked_for_an_unencrypted_key(self):
        """A key stored without a passphrase must not produce a prompt."""
        self.app.keyring.create("plainkey", "Plain", None)
        self.app.keyring.lock("plainkey")
        self.app.refresh_identities()
        try:
            self.assertFalse(self.app.keyring.get("plainkey").encrypted)
            self._refuse_to_prompt()
            self.assertEqual(self.app.ask_unlock("plainkey"), (True, None))
        finally:
            self.app.keyring.delete("plainkey")
            self.app.refresh_identities()

    def test_unlock_refused_for_an_unknown_identity(self):
        proceed, passphrase = self.app.ask_unlock("nobody")
        self.assertFalse(proceed)
        self.assertIsNone(passphrase)
        self.assertTrue(self.errors)
        self.assertIn("Key unavailable", self.errors[0][0])

    def test_unlock_refused_for_a_public_only_identity(self):
        """Encrypting to someone does not mean you can unlock as them."""
        self.app.keyring.import_public(
            KeyPair.generate().public_key.to_compact(), "theironly")
        self.app.refresh_identities()
        try:
            proceed, passphrase = self.app.ask_unlock("theironly")
            self.assertFalse(proceed)
            self.assertIsNone(passphrase)
            self.assertTrue(self.errors)
        finally:
            self.app.keyring.delete("theironly")
            self.app.refresh_identities()

    def test_unlock_returns_the_encoded_passphrase(self):
        self.app.keyring.lock("alice")
        try:
            self.dialogs.ask_passphrase = lambda *a, **k: "pässwörd"
            proceed, passphrase = self.app.ask_unlock("alice")
            self.assertTrue(proceed)
            self.assertEqual(passphrase, "pässwörd".encode("utf-8"))
        finally:
            self.app.keyring.unlock("alice", b"pw")

    # -------------------------------------------------------------- keypair

    def test_keypair_uses_the_cache_without_a_passphrase(self):
        cached = self.app.keyring.cached("alice")
        self.assertIsNotNone(cached)
        self.assertIs(self.app.keypair("alice", None), cached)

    def test_keypair_derives_on_a_cache_miss(self):
        """The worker-thread path when the key was locked at dispatch time."""
        original = self.app.keyring.cached("alice").secret_bytes()
        self.app.keyring.lock("alice")
        self.assertIsNone(self.app.keyring.cached("alice"))
        keypair = self.app.keypair("alice", b"pw")
        self.assertEqual(keypair.secret_bytes(), original)
        self.assertTrue(self.app.keyring.is_unlocked("alice"))

    def test_keypair_rejects_a_wrong_passphrase(self):
        self.app.keyring.lock("alice")
        try:
            with self.assertRaises(PassphraseError):
                self.app.keypair("alice", b"definitely-not-it")
        finally:
            self.app.keyring.unlock("alice", b"pw")

    # ------------------------------------------------------------------ run

    def test_a_second_operation_is_refused_while_one_is_running(self):
        """The guard that stops two crypto jobs racing on the same widgets."""
        import threading

        release = threading.Event()
        finished = []
        self.app.run(lambda _r: release.wait(10), lambda _r: finished.append(True),
                     "first failed")
        try:
            self.assertTrue(self.app.tasks.busy)
            started = []
            self.app.run(lambda _r: started.append(True), None, "second failed")
            self.assertEqual(started, [], "a second job was allowed to start")
            self.assertIn("already running", self.app.status._label.cget("text"))
        finally:
            release.set()
        self.assertTrue(_pump(self.app, lambda: finished))

    def test_an_unexpected_exception_is_surfaced_with_its_type(self):
        """CrsysError shows its message; anything else must name the class too.

        run() also prints the traceback to stderr for unexpected exceptions,
        which is the right behaviour and useless noise in a test run: a suite
        that always prints a traceback teaches you to ignore tracebacks. It is
        captured here so that a stray one still means something.
        """
        reported = []
        noise = io.StringIO()
        with contextlib.redirect_stderr(noise):
            self.app.run(lambda _r: 1 / 0, lambda _r: None, "job failed",
                         on_fail=reported.append)
            self.assertTrue(_pump(self.app, lambda: reported))
        self.assertIn("ZeroDivisionError", reported[0])
        self.assertIn("job failed", self.app.status._label.cget("text"))
        self.assertIn("ZeroDivisionError", noise.getvalue(),
                      "the traceback should still have been written to stderr")

    def test_a_failure_without_a_handler_reaches_a_dialog(self):
        from crsys.errors import CrsysError

        def boom(_report):
            raise CrsysError("something went wrong")

        self.app.run(boom, lambda _r: None, "job failed")
        self.assertTrue(_pump(self.app, lambda: self.errors))
        self.assertEqual(self.errors[0][0], "job failed")
        self.assertIn("something went wrong", self.errors[0][1])


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
