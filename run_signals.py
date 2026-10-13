import json

from scamcheck.signals import detect_signals

with open("samples/messages.json", encoding="utf-8") as f:
    messages = json.load(f)

matches = 0
for msg in messages:
    found = detect_signals(msg["text"])
    found_flags = {s["flag"] for s in found}
    expected = set(msg["expected_flags"])
    missing = expected - found_flags
    extra = found_flags - expected

    if not missing and not extra:
        matches += 1
        status = "OK"
    else:
        status = "MISMATCH"

    print(f"[{status}] {msg['id']} ({msg['label']})")
    for s in found:
        print(f"     found: {s['flag']:<22} <- {s['evidence']}")
    if missing:
        print(f"     MISSING: {sorted(missing)}")
    if extra:
        print(f"     EXTRA:   {sorted(extra)}")

print(f"\n{matches} of {len(messages)} messages match their expected flags.")

# Extra checks for tricky cases the sample messages do not cover.
def flags_of(text):
    return {s["flag"] for s in detect_signals(text)}

assert "otp_request" in flags_of("Please send me your verification code.")
assert "otp_request" not in flags_of("Your code is 123456. Never share this code with anyone.")
assert "otp_request" not in flags_of("Do not share this code with anyone.")
assert "suspicious_link" not in flags_of("Receipt: https://www.amazon.com/your-orders")
assert "suspicious_link" in flags_of("Click here: https://bit.ly/3abcXYZ")
assert "suspicious_link" in flags_of("Login at http://192.168.4.7/verify")
assert flags_of("Lunch tomorrow? I'll bring the notes.") == set()

print("All extra checks passed.")