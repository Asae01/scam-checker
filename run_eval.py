"""Accuracy test on samples/eval_set.json (100 messages the rules were NOT tuned on).

  python run_eval.py          -> rules only (offline, free)
  python run_eval.py ai       -> rules + AI, no web lookups (uses a few cents of credits)
  python run_eval.py full     -> rules + AI + Tavily + website age (uses Tavily credits too)
  add --realistic-domains     -> swap the fake ".example" website names for ".com" ones (rules or ai)

Batch 1 = the first 40 messages. Batch 2 = 60 more, with typos, emoji and more scam types.

Scoring (two classes: scam vs legitimate):
  scam   -> "caught" if the verdict is Likely scam or Suspicious, "strongly" if Likely scam
  legit  -> "clean" if Probably safe, "mild false alarm" if Suspicious, "false alarm" if Likely scam
A markdown summary is saved to eval_results_<mode>.md so you can paste it into the README.
"""

import json
import sys
from concurrent.futures import ThreadPoolExecutor

from scamcheck.pipeline import analyze

args = sys.argv[1:]
realistic = "--realistic-domains" in args
args = [a for a in args if not a.startswith("--")]
mode = args[0] if args else "rules"
if mode not in ("rules", "ai", "full"):
    sys.exit("Use: python run_eval.py [ai|full] [--realistic-domains]")

with open("samples/eval_set.json", encoding="utf-8") as f:
    items = json.load(f)

# The test messages use fake ".example" website names, which an AI can spot as placeholders.
# With --realistic-domains they become ".com" names so the test does not depend on that clue.
# (Do not combine with "full": that would look up made-up names on real registries.)
if realistic:
    if mode == "full":
        sys.exit("Use --realistic-domains with rules or ai, not full.")
    for item in items:
        item["text"] = item["text"].replace(".example", ".com")
suffix = "_realistic" if realistic else ""


def run(item):
    use_ai = mode in ("ai", "full")
    return analyze(item["text"], use_ai=use_ai, use_search=(mode == "full"), use_domain_age=(mode == "full"))


workers = 1 if mode == "rules" else 4
with ThreadPoolExecutor(max_workers=workers) as pool:
    results = list(pool.map(run, items))


def outcome(item, result):
    v = result["verdict"]
    if item["label"] == "scam":
        return "caught strongly" if v == "Likely scam" else "caught" if v == "Suspicious" else "MISSED"
    return "clean" if v == "Probably safe" else "mild false alarm" if v == "Suspicious" else "FALSE ALARM"


rows = [
    {**item, "verdict": r["verdict"], "outcome": outcome(item, r), "ai_used": r["ai_used"], "result": r}
    for item, r in zip(items, results)
]

if mode != "rules" and not any(r["ai_used"] for r in rows):
    sys.exit("The AI did not run (check keys in .env). Nothing to report.")
ai_failures = sum(1 for r in rows if mode != "rules" and not r["ai_used"])

print(f"Mode: {mode}{' (realistic domains)' if realistic else ''}   Messages: {len(rows)}\n")
print(f"{'id':<11}{'level':<6}{'truth':<7}{'verdict':<15}outcome")
for r in rows:
    flag = "  <--" if r["outcome"] in ("MISSED", "FALSE ALARM", "mild false alarm") else ""
    print(f"{r['id']:<11}{r['difficulty']:<6}{r['label']:<7}{r['verdict']:<15}{r['outcome']}{flag}")


def count(subset, label, difficulty, *outcomes):
    pool = [r for r in subset if r["label"] == label and (difficulty is None or r["difficulty"] == difficulty)]
    return sum(1 for r in pool if r["outcome"] in outcomes), len(pool)


lines = []


def table(subset, title):
    lines.extend([f"### {title}", "", "| Group | Result |", "|---|---|"])
    for diff in ("easy", "hard", None):
        name = diff or "all"
        c, n = count(subset, "scam", diff, "caught", "caught strongly")
        s, _ = count(subset, "scam", diff, "caught strongly")
        lines.append(f"| Scams caught ({name}) | {c}/{n} flagged, {s}/{n} as Likely scam |")
    for diff in ("easy", "hard", None):
        name = diff or "all"
        c, n = count(subset, "safe", diff, "clean")
        m, _ = count(subset, "safe", diff, "mild false alarm")
        f_, _ = count(subset, "safe", diff, "FALSE ALARM")
        lines.append(f"| Legitimate left alone ({name}) | {c}/{n} clean, {m} marked Suspicious, {f_} marked Likely scam |")
    lines.append("")


print()
label = mode + (", realistic domains" if realistic else "")
table(rows, f"Accuracy test ({label}): all {len(rows)} messages")
table([r for r in rows if r["batch"] == 1], f"Batch 1 ({label}): original 40")
table([r for r in rows if r["batch"] == 2], f"Batch 2 ({label}): 60 newer messages")
if ai_failures:
    lines.append(f"Note: the AI failed on {ai_failures} message(s), which fell back to rules only.")
    for r in rows:
        if mode != "rules" and not r["ai_used"]:
            lines.append(f"- {r['id']}: {r['result']['ai_error']}")
print("\n".join(lines))

print("\n--- Misses and false alarms (what the checker saw) ---")
for r in rows:
    if r["outcome"] in ("MISSED", "FALSE ALARM", "mild false alarm"):
        print(f"\n{r['id']} [{r['outcome']}] ({r['category']})")
        print("  text:   ", r["text"][:110])
        print("  verdict:", r["verdict"], "| rule score:", r["result"]["risk_score"])
        for s in r["result"]["signals"]:
            print("  rule:   ", s["flag"], "<-", s["evidence"])
        if r["result"]["summary"]:
            print("  AI says:", r["result"]["summary"])

with open(f"eval_results_{mode}{suffix}.md", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print(f"\nSaved eval_results_{mode}{suffix}.md")