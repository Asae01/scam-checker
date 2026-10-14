"""Offline tests for the report message and the daily limit. No keys or credits needed."""

from datetime import date

from scamcheck.limits import DailyLimit
from scamcheck.pipeline import analyze
from scamcheck.report import build_report, defang

# 1. Links are made harmless.
text = "Pay at http://dhl-parcel-redelivery.example/pay or https://www.fastparcelcheck.example/x"
out = defang(text, ["dhl-parcel-redelivery.example", "www.fastparcelcheck.example"])
assert "http://" not in out and "https://" not in out
assert "hxxp://dhl-parcel-redelivery[.]example/pay" in out
assert "hxxps://www[.]fastparcelcheck[.]example/x" in out
# ...but unrelated words that merely contain a domain-like piece are left alone
assert defang("data.company is fine", ["a.co"]) == "data.company is fine"
print("1. Links made harmless: OK")

# 2. A scam produces a full report.
msg = ("DHL: Your parcel is on hold due to an unpaid customs fee of $2.99. Pay within 24 hours: "
       "http://dhl-parcel-redelivery.example/pay Call +1 555 010 0199 or message @quickcashjobs01")
result = analyze(msg, use_ai=False)
report = build_report(result)
assert report.startswith("Subject: Suspected scam message")
assert "Why I think it is a scam:" in report and "Pressures you to act fast" in report
assert "- Website: dhl-parcel-redelivery[.]example" in report
assert "- Phone number: +1 555 010 0199" in report and "- Handle: @quickcashjobs01" in report
assert "http://" not in report and "https://" not in report
assert "dhl-parcel-redelivery.example" not in report  # only the bracketed form appears
print("2. Report for a scam: OK")

# 3. Safe messages get no report.
assert build_report(analyze("Hey, are we still on for dinner at 7?", use_ai=False)) is None
print("3. No report for safe messages: OK")

# 4. AI reasons are used when the AI ran, and long lines are wrapped.
ai_result = dict(result, ai_used=True, red_flags=[{"title": "Fake link http://x.example", "explanation": ""}])
assert "- Fake link hxxp://x.example" in build_report(ai_result)
long = analyze("DHL: pay the customs fee within 24 hours. " + "word " * 80 + "http://dhl-parcel-redelivery.example/x", use_ai=False)
long_report = build_report(long)
assert long_report is not None
assert all(len(line) <= 80 for line in long_report.splitlines())
print("4. AI reasons and wrapping: OK")

# 5. Daily limit: allows N per day, then refuses, then resets on a new day.
today = {"d": date(2026, 12, 1)}
limit = DailyLimit(3, today=lambda: today["d"])
assert [limit.take() for _ in range(5)] == [True, True, True, False, False]
today["d"] = date(2026, 12, 2)
assert limit.take() is True
print("5. Daily limit and reset: OK")

print("\nAll report and limit tests passed.")