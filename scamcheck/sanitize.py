"""Clean a pasted message before anything else looks at it.

What it does:
- Normalises look-alike characters (full-width letters, ligatures) so the rule checks
  are not fooled by them.
- Removes invisible characters (zero-width spaces, "right-to-left override" and similar).
  Scammers use them to dodge filters, and they can hide text from a human reader.
  We count them, because a message full of them is itself suspicious.
- Removes other control characters and collapses huge runs of blank lines.
- Hides card numbers and ID numbers, so they are never sent to the AI or a search service.
"""

import re
import unicodedata

# Characters with no visible shape. U+200D (used inside emoji) is deliberately kept.
_INVISIBLE_RE = re.compile("[\u200b\u2060\ufeff\u00ad]")
# "Bidi" controls can reorder text on screen, so a link can look different from what it is.
_BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
# Control characters, except tab, newline and carriage return.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_BLANK_LINES_RE = re.compile(r"\n{3,}")
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _luhn_ok(digits):
    """The checksum every real card number passes."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def clean_message(text):
    """Return (cleaned text, info). info counts what was changed."""
    text = unicodedata.normalize("NFKC", str(text or ""))
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    bidi = len(_BIDI_RE.findall(text))
    hidden = len(_INVISIBLE_RE.findall(text))
    text = _INVISIBLE_RE.sub("", _BIDI_RE.sub("", text))
    text = _CONTROL_RE.sub("", text)
    text = _BLANK_LINES_RE.sub("\n\n", text).strip()

    cards = 0

    def mask_card(match):
        nonlocal cards
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            cards += 1
            return "[card number hidden]"
        return match.group(0)

    text = _CARD_RE.sub(mask_card, text)
    ids = len(_SSN_RE.findall(text))
    text = _SSN_RE.sub("[ID number hidden]", text)

    return text, {
        "hidden_chars": hidden,
        "bidi_controls": bidi,
        "cards_masked": cards,
        "ids_masked": ids,
    }