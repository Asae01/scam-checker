"""Tests for the screen (Streamlit's headless test mode). No keys, internet or browser needed."""

import testenv  # noqa: F401  (offline test environment: must come first)
import re
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

SCAM = "DHL: Your parcel is on hold. Pay the customs fee within 24 hours: http://dhl-parcel-redelivery.example/pay"


def fresh():
    return AppTest.from_file("app.py", default_timeout=60).run()


def check(at, text):
    at.text_area(key="message").set_value(text).run()
    at.button(key="check").click().run()
    return at


def cards(at):
    return [m.value for m in at.markdown if 'class="verdict-card' in m.value]


def texts(at):
    return [m.value for m in at.markdown] + [c.value for c in at.caption] + [i.value for i in at.info]


# 1. A scam: red card, steps shown first, three tabs, harmless report.
at = check(fresh(), SCAM)
assert not at.exception, at.exception
card = cards(at)[0]
assert "v-scam" in card and "Likely scam" in card and "http://" not in card
assert any(s.value == "What to do now" for s in at.subheader)
assert [t.label for t in at.tabs] == ["What stood out", "Report it", "Details"]
assert len(at.code) == 1 and "http://" not in at.code[0].value
print("1. Scam: card, steps, tabs, report: OK")

# 2. Normal message: green card, no report tab.
at = check(fresh(), "Hey, are we still on for dinner at 7?")
assert not at.exception, at.exception
assert "v-safe" in cards(at)[0] and [t.label for t in at.tabs] == ["What stood out", "Details"] and not list(at.code)
print("2. Safe message: green card, no report: OK")

# 3. Example buttons fill the box; editing afterwards warns that the result is old.
at = fresh()
at.button(key="ex_scam_01_delivery_fee").click().run()
assert "DHL" in at.text_area(key="message").value
at.button(key="check").click().run()
assert not any("You changed the message" in i for i in texts(at))
at.text_area(key="message").set_value("something else").run()
assert any("You changed the message" in i for i in texts(at))
print("3. Examples and stale-result notice: OK")

# 4. Clear removes the text and the result.
at.button(key="clear").click().run()
assert at.text_area(key="message").value == "" and not cards(at)
print("4. Clear: OK")

# 5. Empty message -> friendly warning.
at = fresh()
at.button(key="check").click().run()
assert [w.value for w in at.warning] == ["Please paste a message to check."] and not cards(at)
print("5. Empty message: OK")

# 6. Daily limit reached -> rules only, with a note; the AI is never called.
with patch("scamcheck.limits.DailyLimit.take", return_value=False), patch("scamcheck.pipeline.ask_model") as ask:
    at = check(fresh(), SCAM)
    assert not at.exception and not ask.called
    assert any("paused right now" in i for i in texts(at)) and "Likely scam" in cards(at)[0]
print("6. Limit reached -> rules only: OK")

# 7. A crash inside the checker shows a friendly message and leaks nothing.
with patch("scamcheck.pipeline.analyze", side_effect=RuntimeError("secret detail 12345")):
    at = check(fresh(), SCAM)
    assert not at.exception
    assert [e.value for e in at.error] == ["Sorry, something went wrong while checking. Please try again in a moment."]
    everything = " ".join(texts(at) + [e.value for e in at.error] + [w.value for w in at.warning])
    assert "secret detail" not in everything and "RuntimeError" not in everything
print("7. Errors are friendly and leak nothing: OK")

# 8. Hostile AI text cannot inject markup or make links clickable.
hostile = {"verdict": "Likely scam", "confidence": "high",
           "summary": "<script>alert(1)</script> Visit http://evil.example or www.evil.example now",
           "red_flags": [{"title": "<img src=x onerror=alert(2)>", "explanation": "[click](http://x.example)"}],
           "next_steps": ["<b>Delete it</b> http://y.example"]}
with patch("scamcheck.pipeline.ask_model", return_value=(hostile, None)):
    at = check(fresh(), SCAM)
    assert not at.exception, at.exception
    card = cards(at)[0]
    assert "<script" not in card and "http://" not in card and "&lt;script&gt;" in card
    everything = " ".join(m.value for m in at.markdown)
    for bad in ("http://evil.example", "http://x.example", "http://y.example"):
        assert bad not in everything, bad
    for tag in ("<img", "<script", "<b>"):  # an escaped "\\<img" is shown as plain text, so it is fine
        assert not re.search(r"(?<!\\)" + re.escape(tag), everything), tag
print("8. Hostile AI text stays harmless: OK")

# 9. Card numbers are hidden and the visitor is told.
at = check(fresh(), "Please charge card 4111 1111 1111 1111 and pay the customs fee within 24 hours")
assert any("hid 1 card or ID number" in i for i in texts(at))
assert "4111" not in " ".join(m.value for m in at.markdown)
print("9. Card numbers hidden and visitor told: OK")

# 10. The cleaned message is what gets highlighted, with links harmless.
at = check(fresh(), SCAM)
marks = [m.value for m in at.markdown if "<mark" in m.value]
assert len(marks) == 1 and "hxxp://dhl-parcel-redelivery[.]example/pay" in marks[0]
print("10. Highlighted message is harmless: OK")

print("\nAll screen tests passed.")