"""Offline tests for highlighting. Checks the output cannot inject markup or links."""

import testenv  # noqa: F401  (offline test environment: must come first)
from scamcheck.highlight import highlight_html, merge_spans
from scamcheck.pipeline import analyze

# 1. Matches are highlighted.
msg = "DHL: Your parcel is on hold due to an unpaid customs fee of $2.99. Pay within 24 hours: http://dhl-parcel-redelivery.example/pay"
r = analyze(msg, use_ai=False)
out = highlight_html(r["message"], r["signals"], r["facts"]["domains"])
assert "<mark" in out
assert ">within 24 hours</mark>" in out and ">customs fee</mark>" in out
print("1. Matches highlighted: OK")

# 2. Links are made harmless.
assert "http://" not in out and "hxxp://" in out and "dhl-parcel-redelivery[.]example" in out
print("2. Links made harmless: OK")

# 3. Hostile text cannot inject markup, and blank lines cannot break out of the block.
evil = "<script>alert(1)</script> <img src=x onerror=alert(2)>\n\n[click](http://x.example)\n\nPay the customs fee within 24 hours"
r = analyze(evil, use_ai=False)
out = highlight_html(r["message"], r["signals"], r["facts"]["domains"])
assert "<script" not in out and "<img" not in out
assert "&lt;script&gt;" in out and "&lt;img" in out
assert "\n" not in out, "raw newlines (blank lines) could end the HTML block"
assert out.count("<mark") == out.count("</mark>") and out.startswith("<div") and out.endswith("</div>")
print("3. Hostile text stays text: OK")

# 4. Overlapping ranges merge into one.
sigs = [{"label": "A", "span": (0, 10)}, {"label": "B", "span": (5, 20)}, {"label": "C", "span": (30, 35)}, {"label": "D", "span": None}]
assert merge_spans(sigs) == [(0, 20, ["A", "B"]), (30, 35, ["C"])]
print("4. Overlaps merged: OK")

# 5. Nothing to highlight -> None.
r = analyze("Hey, are we still on for dinner at 7?", use_ai=False)
assert highlight_html(r["message"], r["signals"], r["facts"]["domains"]) is None
print("5. Nothing flagged -> nothing highlighted: OK")

print("\nAll highlight tests passed.")