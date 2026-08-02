"""Design tokens, and the accent applied globally to CustomTkinter.

Two constraints shaped the palette.

Green, amber and red are **taken**: they carry the signature verdict, which is
the most important thing this interface says. The accent has to sit outside that
range, or the one colour a user must read correctly ends up competing with
decoration. Indigo is far enough away.

And the default CustomTkinter blue is avoided deliberately. It is the colour
every untouched CTk project ships with, so it reads as "nobody chose this"
before anyone has looked at anything else.

Colours are ``(light, dark)`` pairs; CustomTkinter picks per appearance mode.
"""

from __future__ import annotations

import customtkinter as ctk

# --------------------------------------------------------------------- spacing

# A 4-point scale. One uniform padding value everywhere is what made the first
# version read as a settings dialog: if everything is equally far from
# everything else, nothing groups.
SPACE_XS = 4
SPACE_S = 8
SPACE_M = 16
SPACE_L = 24
SPACE_XL = 32

PAD = SPACE_M
PAD_S = SPACE_S

# ---------------------------------------------------------------- typography

# Four steps, far enough apart to read as a hierarchy. The previous 15/13/11
# were too close together to signal anything.
SIZE_DISPLAY = 21
SIZE_TITLE = 15
SIZE_BODY = 13
SIZE_CAPTION = 11

TITLE_SIZE = SIZE_TITLE
BODY_SIZE = SIZE_BODY
SMALL_SIZE = SIZE_CAPTION

MONO = "Consolas"

# ------------------------------------------------------------------- palette

ACCENT = ("#4F46E5", "#5B54E8")
ACCENT_HOVER = ("#4338CA", "#7069EE")
ACCENT_MUTED = ("#EEF0FE", "#26264A")

TEXT_PRIMARY = ("#11131A", "#E8EAF0")
TEXT_SECONDARY = ("#454B58", "#A8AEBD")
MUTED_FG = ("#6B7280", "#868D9E")

# Semantic states. These are the interface's actual message; nothing decorative
# may use them.
OK_FG = ("#166534", "#4ADE80")
WARN_FG = ("#92400E", "#FBBF24")
ERROR_FG = ("#B42318", "#F87171")

OK_BG = ("#ECFDF3", "#0E2A18")
WARN_BG = ("#FFFAEB", "#2B2008")
ERROR_BG = ("#FEF3F2", "#2C1315")
NEUTRAL_BG = ("#F2F4F7", "#22242B")

CARD_BG = ("#F7F8FA", "#1E2026")
SURFACE_RAISED = ("#FFFFFF", "#24262E")
SELECTED_BG = ("#E5E7FB", "#2A2C57")
BORDER = ("#E4E7EC", "#33363F")

RADIUS = 8
RADIUS_CONTROL = 6


def apply() -> None:
    """Override the CustomTkinter defaults before any widget is built.

    ThemeManager.theme is a plain dict read at widget construction, so mutating
    it here reaches every widget without threading colours through every call.
    """
    theme = ctk.ThemeManager.theme

    for key in ("CTkButton", "CTkOptionMenu", "CTkComboBox", "CTkCheckBox",
                "CTkRadioButton", "CTkSwitch", "CTkSlider", "CTkProgressBar",
                "CTkSegmentedButton"):
        entry = theme.get(key)
        if entry is None:
            continue
        for field in ("fg_color", "progress_color", "selected_color",
                      "button_color"):
            if field in entry:
                entry[field] = list(ACCENT)
        for field in ("hover_color", "selected_hover_color", "button_hover_color"):
            if field in entry:
                entry[field] = list(ACCENT_HOVER)

    # The unselected half of a segmented button should recede, not compete.
    segmented = theme.get("CTkSegmentedButton")
    if segmented is not None:
        segmented["fg_color"] = list(NEUTRAL_BG)
        segmented["unselected_color"] = list(NEUTRAL_BG)
        segmented["unselected_hover_color"] = list(CARD_BG)
        segmented["border_width"] = 0

    if "CTkFrame" in theme:
        theme["CTkFrame"]["corner_radius"] = RADIUS
        theme["CTkFrame"]["fg_color"] = list(CARD_BG)
        theme["CTkFrame"]["top_fg_color"] = list(SURFACE_RAISED)
        theme["CTkFrame"]["border_color"] = list(BORDER)

    # A 2px border is the single most dated thing in the default theme.
    for key in ("CTkEntry", "CTkTextbox"):
        if key in theme:
            theme[key]["border_width"] = 1
            theme[key]["corner_radius"] = RADIUS_CONTROL
            theme[key]["border_color"] = list(BORDER)
            theme[key]["fg_color"] = list(SURFACE_RAISED)

    if "CTkScrollableFrame" in theme:
        theme["CTkScrollableFrame"]["label_fg_color"] = list(CARD_BG)

    for key in ("CTkButton", "CTkOptionMenu", "CTkCheckBox"):
        if key in theme:
            theme[key]["corner_radius"] = RADIUS_CONTROL
