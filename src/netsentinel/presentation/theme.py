"""Shared styles using the current Qt palette, scoped away from the light sidebar."""

PAGE_TITLE = "font-size: 24px; font-weight: 700; color: palette(window-text);"
SECONDARY_TEXT = "color: palette(window-text);"
CARD_TITLE = "font-size: 16px; font-weight: 600; color: palette(window-text);"
METRIC_VALUE = "font-size: 25px; font-weight: 700; color: palette(window-text);"


def card_style(object_name: str) -> str:
    return (
        f"QFrame#{object_name} {{ background: palette(alternate-base); "
        "color: palette(window-text); border: 1px solid palette(mid); border-radius: 6px; }"
        f"QFrame#{object_name} QLabel {{ color: palette(window-text); background: transparent; border: 0; }}"
    )
