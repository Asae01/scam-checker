import json

from scamcheck.pipeline import analyze

with open("samples/messages.json", encoding="utf-8") as f:
    messages = json.load(f)

LABEL_TO_VERDICT = {
    "scam": "Likely scam",
    "suspicious": "Suspicious",
    "safe": "Probably safe",
}

correct = 0
for msg in messages:
    result = analyze(msg["text"], use_ai=False)
    expected = LABEL_TO_VERDICT[msg["label"]]
    ok = result["verdict"] == expected
    correct += ok
    mark = "OK      " if ok else "DIFFERENT"
    print(f"[{mark}] {msg['id']:<32} score={result['risk_score']:<2} "
          f"verdict={result['verdict']:<14} (expected {expected})")

print(f"\n{correct} of {len(messages)} verdicts match the expected label.")

# Edge cases.
try:
    analyze("   ", use_ai=False)
except ValueError as error:
    print("Empty message handled:", error)

long_result = analyze("hello " * 1000, use_ai=False)
print("Long message cut off:", long_result["was_truncated"])