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

# 11. The first screen: hero, ONE set of example buttons (no old dropdown), empty state, how-it-works.
at = fresh()
assert not at.exception, at.exception
first = [m.value for m in at.markdown]
assert any('class="hero"' in m and "<h1" in m for m in first)
assert any('class="empty-state"' in m and "Your result appears here" in m for m in first)
assert any('class="how-grid"' in m for m in first)
assert not cards(at)
assert len(at.selectbox) == 0, "the old example dropdown must not come back"
example_keys = sorted(b.key for b in at.button if b.key and b.key.startswith("ex_"))
assert example_keys == ["ex_safe_03_friend_dinner", "ex_safe_04_real_otp",
                        "ex_scam_01_delivery_fee", "ex_scam_03_otp_request"], example_keys
print("11. First screen: hero, empty state, one set of examples: OK")

# 12. The summary sits INSIDE the verdict card, and the empty state goes away once there is a result.
ai = {"verdict": "Likely scam", "confidence": "high", "summary": "Pretends to be a courier and asks for money.",
      "red_flags": [], "next_steps": ["Do not pay."]}
with patch("scamcheck.pipeline.ask_model", return_value=(ai, None)):
    at = check(fresh(), SCAM)
    assert not at.exception, at.exception
    card = cards(at)[0]
    assert "Pretends to be a courier" in card and "High risk" in card and "Confidence: high" in card
    assert "<svg" in card and "http://" not in card
    assert not any('class="empty-state"' in m.value for m in at.markdown)
    assert any("steps-card" in m.value and "Do not pay." in m.value for m in at.markdown)
print("12. Summary inside the card, empty state replaced: OK")

# 13. The privacy text tells the whole truth (every service that sees something).
at = fresh()
privacy = " ".join(m.value for exp in at.expander for m in exp.markdown)
for must_say in ("does not store", "Nebius", "Tavily", "RDAP", "Card and ID numbers are hidden"):
    assert must_say in privacy, must_say
print("13. Privacy text is complete: OK")

# 14. Every icon is a trusted constant: no scripts, no external links, labelled decorative.
source = open("app.py", encoding="utf-8").read()
svg_block = source[source.index("_SVG ="): source.index("STYLE =")]
assert "http://" not in svg_block
assert "xmlns" not in svg_block and "<script" not in svg_block.lower() and "href" not in svg_block.lower()
assert 'aria-hidden="true"' in svg_block and 'focusable="false"' in svg_block
assert len(re.findall(r"ICON_[A-Z]+ =", svg_block)) == 4
print("14. Icons are safe: OK")

# 15. Real animation: keyframes exist, the old "switch everything off" rule is gone, and people who
#     ask for reduced motion still get none.
source = open("app.py", encoding="utf-8").read()
style = source[source.index("STYLE ="): source.index("HERO =")]
assert "@keyframes bounce" in style and "@keyframes rise" in style and "@keyframes pop" in style
assert "animation: none" not in style and "transition: none" not in style
reduced = style[style.index("prefers-reduced-motion"):]
assert "animation-duration: 0.01ms" in reduced and "transition-duration: 0.01ms" in reduced
print("15. Animations present, accessibility switch present: OK")

# 16. The loader is a fixed snippet with no user text, appears BEFORE the slow check runs,
#     and is always cleared afterwards (even after an error).
loader_text = source[source.index("LOADER ="): source.index("HOW_IT_WORKS =")]
assert "{" not in loader_text and 'role="status"' in loader_text and "Checking the message..." in loader_text
run_check_text = source[source.index("def run_check"): source.index("def render_result")]
assert run_check_text.index("loader.markdown") < run_check_text.index("analyze(message")
assert "finally:" in run_check_text and "loader.empty()" in run_check_text
for patched in (None, RuntimeError("boom")):
    if patched is None:
        at = check(fresh(), SCAM)
    else:
        with patch("scamcheck.pipeline.analyze", side_effect=patched):
            at = check(fresh(), SCAM)
    assert not at.exception, at.exception
    assert not any('class="loader"' in m.value for m in at.markdown), "the loader was left on screen"
print("16. Loader is safe, shown first, always cleared: OK")

# 17. Tabs have room above them and a styled bar.
assert '[data-testid="stTabs"] { margin-top: 1.5rem; }' in style
assert "box-shadow" in style[style.index('[role="tablist"]'):][:400]
print("17. Tab spacing and styling present: OK")

print("\nAll screen tests passed.")