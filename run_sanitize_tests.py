"""Offline tests for message cleaning. No keys or internet needed."""

import testenv  # noqa: F401  (offline test environment: must come first)
import json
import os
from types import SimpleNamespace

from scamcheck.llm import ask_model
from scamcheck.pipeline import analyze
from scamcheck.sanitize import clean_message

os.environ["NEBIUS_MODEL_ID"] = "test-model"  # the AI step is skipped without a model ID

# 1. Invisible characters are removed and counted; emoji joiners are kept.
text, info = clean_message("fr\u200bee pr\u200bize\u200b and \ufeffwin")
assert text == "free prize and win" and info["hidden_chars"] == 4
family = "\U0001F468\u200d\U0001F469\u200d\U0001F467"
assert clean_message(family)[0] == family
print("1. Invisible characters removed, emoji kept: OK")

# 2. Text-direction tricks are removed and counted.
text, info = clean_message("pay at \u202etpircs.com\u202c now")
assert "\u202e" not in text and info["bidi_controls"] == 2
print("2. Direction controls removed: OK")

# 3. Look-alike characters are normalised so the rules are not fooled.
assert clean_message("\uff30ay within 24 hours")[0] == "Pay within 24 hours"
assert clean_message("\ufb01nal notice")[0] == "final notice"
print("3. Look-alike letters normalised: OK")

# 4. Control characters go, newlines and tabs stay, blank lines collapse.
text, _ = clean_message("a\x00b\x07c\nd\te\n\n\n\n\nf")
assert text == "abc\nd\te\n\nf"
print("4. Control characters and blank lines: OK")

# 5. Card numbers are hidden (only checksum-valid ones); phone numbers and prices are not.
text, info = clean_message("My card is 4111 1111 1111 1111 and 4111-1111-1111-1111, exp 12/29")
assert text.count("[card number hidden]") == 2 and "4111" not in text and info["cards_masked"] == 2
text, info = clean_message("Call +1 555 010 0199 or pay $1,234.56 for order 1234567890123")
assert "555 010 0199" in text and "$1,234.56" in text and info["cards_masked"] == 0
text, info = clean_message("my id is 123-45-6789")
assert "123-45-6789" not in text and info["ids_masked"] == 1
print("5. Card and ID numbers hidden, phones and prices kept: OK")

# 6. Hidden characters help scammers dodge the rules; cleaning defeats that.
sneaky = "Pay the cus\u200btoms f\u200bee with\u200bin 24 ho\u200burs: http://dhl-parcel-redelivery.example/pay"
r = analyze(sneaky, use_ai=False)
assert {"fee_request", "urgency"} <= {s["flag"] for s in r["signals"]}
assert r["privacy"]["hidden_chars"] == 4
assert "hidden_characters" in {s["flag"] for s in r["signals"]}  # 4 is over the limit of 3
print("6. Rules still work on text with hidden characters: OK")

# 7. Many hidden characters, or any direction control, is itself a red flag.
many = "hel\u200blo " * 3 + "there"
assert "hidden_characters" in {s["flag"] for s in analyze(many, use_ai=False)["signals"]}
assert "hidden_characters" in {s["flag"] for s in analyze("see \u202egoogle.com", use_ai=False)["signals"]}
assert "hidden_characters" not in {s["flag"] for s in analyze("Hello \U0001F468\u200d\U0001F469 there", use_ai=False)["signals"]}
print("7. Hidden-character flag: OK")

# 8. The card number never reaches the AI prompt, and the cleaned text is what is shown.
class Spy:
    def __init__(self):
        self.prompt = None
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.prompt = kwargs["messages"][1]["content"]
        reply = json.dumps({"verdict": "Suspicious", "confidence": "low", "summary": "x", "red_flags": [], "next_steps": []})
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))])

spy = Spy()
r = analyze("Charge my card 4111 1111 1111 1111 please", client=spy, use_search=False, use_domain_age=False)
assert "4111" not in spy.prompt and "[card number hidden]" in spy.prompt
assert "4111" not in r["message"] and r["privacy"]["cards_masked"] == 1
print("8. Card number never sent to the AI: OK")

# 9. A message that is only invisible characters counts as empty.
try:
    analyze("\u200b\u200b \ufeff", use_ai=False)
    raise AssertionError("should have refused")
except ValueError:
    pass
print("9. Only-invisible message treated as empty: OK")

# 10. The AI is asked a second time when its first reply is unreadable.
class Flaky:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls += 1
        reply = self.replies.pop(0)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))])

good = json.dumps({"verdict": "Likely scam", "confidence": "high", "summary": "ok", "red_flags": [], "next_steps": []})
flaky = Flaky(["sorry, here is my answer in words", good])
result, error = ask_model("msg", {"domains": [], "phones": [], "handles": []}, [], client=flaky)
assert result["verdict"] == "Likely scam" and error is None and flaky.calls == 2
never = Flaky(["nope", "still nope"])
result, error = ask_model("msg", {"domains": [], "phones": [], "handles": []}, [], client=never)
assert result is None and "understood" in error and never.calls == 2
print("10. Retry on unreadable AI reply: OK")

print("\nAll cleaning tests passed.")