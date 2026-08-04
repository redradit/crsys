# Contributing

[SECURITY.md](SECURITY.md) says findings against the protocol design are the
most welcome kind, because that is the part of this project nobody outside it has
reviewed. This file is what you need to act on that.

## Set up

```bash
python -m pip install -e ".[gui,argon2,dev]"
```

Python 3.9 or later. `gui` pulls in customtkinter, `argon2` enables Argon2id
(scrypt is used when it is absent), `dev` pins the linters.

## Run the tests

```bash
python tests/run_all.py
```

289 tests, about 22 seconds. Useful variations:

```bash
python tests/run_all.py -v              # per-test names
python tests/run_all.py tamper signing  # only modules matching these
python tests/run_all.py -x gui          # everything except the GUI
```

Modules: `keys`, `kdf`, `container`, `tamper`, `defensive`, `signing`,
`streaming`, `vectors`, `fuzz`, `cli`, `gui`.

Every run prints the slowest tests. That is not decoration — CI failures on one
configuration once correlated with how long the job took rather than with any
code change, and a suite that cannot say where its time goes leaves you guessing
at exactly the moment you need a fact.

The GUI tests open a real window with the event loop pumped by hand. On Linux
they need a display, so CI runs them under `xvfb-run -a`; without one they skip
themselves, which silently leaves a quarter of the suite unrun. If a wait fails
on a slow machine rather than because of your change, raise `CRSYS_TEST_TIMEOUT`
(seconds, default 60; CI uses 300).

## Lint and types

```bash
python -m ruff check .
python -m mypy
```

Both must be clean; both block in CI. Paths and settings live in
`pyproject.toml`, so a local run and CI cannot drift.

The configuration is curated, not maximal, and every rule family left out has
its reason written beside it. If a rule fires on something deliberate, add a
narrow `# noqa: RULE` **with the reason on the adjacent line** rather than
widening the ignore list. If it fires on something real, fix it.

Two things are deliberately absent: `ruff format` and import sorting. Both were
measured before being rejected — the formatter would rewrite 28 of 36 files
(+1703/-769 lines), reflowing hand-aligned signatures and the comment layout
that carries most of the reasoning here.

## The wire format is frozen

This is the rule that matters most.

The container format is version `1`. `tests/vectors.json` pins the exact bytes
of nine containers, and `tests/test_vectors.py` checks them on every run. That
file exists so an independent implementation is possible to write and check
against something other than this code reading its own mind.

So: **a change that alters the bytes on the wire is not a bug fix, it is a new
format version.** It needs the version bumped, [SPEC.md](SPEC.md) updated —
SPEC.md is normative, not descriptive — and regenerated vectors:

```bash
python tests/make_vectors.py
```

If `test_vectors` fails and you did not intend a format change, that is the test
doing its job. Do not regenerate the vectors to make it pass.

A change that only alters which *keys* or *inputs* are accepted is different,
and does not need a format version — rejecting a small-order key does not change
any container's encoding.

## Fuzzing

```bash
python tests/test_fuzz.py --iterations 500000 --seed 1
```

A seeded, structure-aware mutation fuzzer over the container, armor and key-file
parsers. A short campaign runs inside the normal suite; CI runs a long one
weekly with a fresh seed. A failure prints the seed needed to replay it — put
that seed in the report.

The invariant is stronger than "must not crash": on a binary container, **any**
mutation that changes the bytes must be rejected, because a success would mean
part of the container is malleable. Only `CrsysError` may escape a parser; a
`ValueError` or `IndexError` reaching the caller means malformed input got into
code that assumed otherwise. Four of the defects in the README were found this
way.

## Coverage

CI enforces 90% on `crsys/` and will fail below it; it currently sits at 95%.

A caveat about that number: coverage is measured on Linux only, and the two
platforms have complementary blind spots. The POSIX `os.chmod` branch of
`restrict_to_owner` cannot run on Windows, and the `icacls` branch beside it
cannot run on Linux, so **neither platform's figure is the whole truth**. If you
touch that function, run the suite on both.

`crsys/__main__.py` reports 0% and is nonetheless tested — `python -m crsys` runs
in a subprocess, which the parent's coverage does not follow. The GUI is measured but not
gated: its modal dialogs are replaced by automatic answers in tests by design,
and folding them into one number would produce a figure that means nothing.

## Style

Match the surrounding code rather than your own habits. Specifically:

- `%`-formatting, not f-strings; `os.path`, not `pathlib`; `unittest`, not
  pytest. These are choices, and the linter is configured not to argue with
  them.
- 88 columns. Measured, not copied from a template: 0.4% of lines exceed it and
  none exceed 100.
- **Comments explain why, not what.** This codebase is unusually comment-dense
  and the comments carry the reasoning — which attack a check exists for, which
  RFC requires it, what was tried and failed. A comment restating the code is
  worse than none. If you fix something subtle, the comment explaining why is
  the more valuable half of the patch.
- Commit messages are long here on purpose, and describe the reasoning and what
  was ruled out, not just the change. `git log` is the design record.

## Reporting a security finding

Open an issue for anything non-sensitive. For something that would put existing
users at risk, use GitHub's private security advisory feature first rather than a
public issue — see [SECURITY.md](SECURITY.md).

Include a reproduction if you can. If it is a protocol-level argument rather than
a crash, state the assumed attacker capability explicitly; that is usually where
these conversations turn out to hinge.
