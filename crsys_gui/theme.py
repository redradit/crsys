"""Visual constants shared by the panels.

Colours are ``(light, dark)`` pairs: CustomTkinter picks the right one for the
active appearance mode, so every label stays readable in both.
"""

from __future__ import annotations

PAD = 12
PAD_S = 6

# Semantic states. Green = verified, amber = a guarantee is missing, red = rejected.
OK_FG = ("#1a7f37", "#3fb950")
WARN_FG = ("#9a6700", "#d29922")
ERROR_FG = ("#cf222e", "#f85149")
MUTED_FG = ("gray40", "gray60")

OK_BG = ("#dafbe1", "#12261a")
WARN_BG = ("#fff8c5", "#2b2413")
ERROR_BG = ("#ffebe9", "#2d1618")
NEUTRAL_BG = ("gray92", "gray20")

CARD_BG = ("gray95", "gray17")
SELECTED_BG = ("#cfe4ff", "#1f3a5f")

MONO = "Consolas"

TITLE_SIZE = 15
BODY_SIZE = 13
SMALL_SIZE = 11
