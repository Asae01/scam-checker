"""False-alarm test on the public SMS Spam Collection (rules only: free and offline).

How to get the data (do NOT commit it to your repo):
  1. Download "SMS Spam Collection" from the UCI Machine Learning Repository
     (the original UCI page, not a copy). Read its license and credit the authors:
     Almeida and Gomez Hidalgo.
  2. Put the zip (or the extracted file called SMSSpamCollection) in a folder
     called data/ and add the line  data/  to your .gitignore.

Run:
  python run_dataset_check.py                       -> uses data/SMSSpamCollection
  python run_dataset_check.py path/to/file.zip      -> or give a path (zip or text)

The file has one message per line: "ham" or "spam", a tab, then the text.
The ham (normal) messages are the useful part: they show how often normal texts
are wrongly flagged. The spam is older general spam, so it says little about
modern scams. Only counts are saved to the results file, never message text.
"""

import collections
import sys
import zipfile

from scamcheck.pipeline import analyze

path = sys.argv[1] if len(sys.argv) > 1 else "data/SMSSpamCollection"


def load(file_path):
    try:
        if file_path.lower().endswith(".zip"):
            with zipfile.ZipFile(file_path) as z:
                name = next(n for n in z.namelist() if n.endswith("SMSSpamCollection"))
                raw = z.read(name).decode("utf-8", errors="replace")
        else:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                raw = f.read()
    except (OSError, StopIteration, zipfile.BadZipFile) as error:
        sys.exit(f"Could not read {file_path}: {type(error).__name__}. See the instructions at the top of this file.")
    rows = []
    for line in raw.splitlines():
        label, sep, text = line.partition("\t")
        if sep and label in ("ham", "spam") and text.strip():
            rows.append((label, text.strip()))
    return rows


rows = load(path)
if not rows:
    sys.exit("No messages found. The file should have lines like: ham<TAB>message text")

verdicts = {"ham": collections.Counter(), "spam": collections.Counter()}
ham_flag_counts = collections.Counter()
flagged_ham = []

for label, text in rows:
    result = analyze(text, use_ai=False)
    verdicts[label][result["verdict"]] += 1
    if label == "ham" and result["verdict"] != "Probably safe":
        flagged_ham.append((result["verdict"], text, [s["flag"] for s in result["signals"]]))
        for s in result["signals"]:
            ham_flag_counts[s["flag"]] += 1


def pct(part, whole):
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


ham_n, spam_n = sum(verdicts["ham"].values()), sum(verdicts["spam"].values())
ham_clean = verdicts["ham"]["Probably safe"]
ham_susp, ham_scam = verdicts["ham"]["Suspicious"], verdicts["ham"]["Likely scam"]
spam_flagged = spam_n - verdicts["spam"]["Probably safe"]

lines = [
    "### False-alarm test on the SMS Spam Collection (rules only)",
    "",
    "| Group | Messages | Result |",
    "|---|---|---|",
    f"| Normal messages (ham) | {ham_n} | {ham_clean} left alone ({pct(ham_clean, ham_n)}), "
    f"{ham_susp} marked Suspicious ({pct(ham_susp, ham_n)}), {ham_scam} marked Likely scam ({pct(ham_scam, ham_n)}) |",
    f"| Spam | {spam_n} | {spam_flagged} flagged ({pct(spam_flagged, spam_n)}), "
    f"{verdicts['spam']['Likely scam']} as Likely scam ({pct(verdicts['spam']['Likely scam'], spam_n)}) |",
    "",
    "Rules that fired most often on normal messages:",
    "",
] + [f"- {flag}: {n}" for flag, n in ham_flag_counts.most_common(8)] + [""]
print("\n".join(lines))

flagged_ham.sort(key=lambda item: item[0] != "Likely scam")  # most serious first
print("\nFirst 15 normal messages that were flagged, most serious first (check these by hand; they are real people's texts, so do not share them):")
for verdict, text, flags in flagged_ham[:15]:
    print(f"  [{verdict}] {text[:100]!r}  <- {', '.join(flags)}")

with open("dataset_check_results.md", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print("\nSaved dataset_check_results.md (counts only)")