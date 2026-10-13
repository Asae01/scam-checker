"""Accuracy test on samples/eval_set.json (40 messages the rules were NOT tuned on).

  python run_eval.py          -> rules only (offline, free)
  python run_eval.py ai       -> rules + AI, Tavily search OFF (uses a few cents of credits)
  python run_eval.py full     -> rules + AI + Tavily (uses Tavily credits too)

Scoring (two classes: scam vs legitimate):
  scam      -> "caught" if verdict is Likely scam or Suspicious, "strongly" if Likely scam
  legit     -> "clean" if Probably safe, "mild false alarm" if Suspicious, "false alarm" if Likely scam
A markdown summary is saved to eval_results_<mode>.md so you can paste it into the README.
"""

import json
import sys
from concurrent.futures import ThreadPoolExecutor

from scamcheck.pipeline import analyze

mode = sys.argv[1] if len(sys.argv) > 1 else "rules"
if mode not in ("rules", "ai", "full"):
    sys.exit("Use: python run_eval.py [ai|full]")

with open("samples/eval_set.json", encoding="utf-8") as f:
    items = json.load(f)


def run(item):
    use_ai = mode in ("ai", "full")
    return analyze(item["text"], use_ai=use_ai, use_search=(mode == "full"))


workers = 1 if mode == "rules" else 4
with ThreadPoolExecutor(max_workers=workers) as pool:
    results = list(pool.map(run, items))


def outcome(item, result):
    v = result["verdict"]
    if item["label"] == "scam":
        return "caught strongly" if v == "Likely scam" else "caught" if v == "Suspicious" else "MISSED"
    return "clean" if v == "Probably safe" else "mild false alarm" if v == "Suspicious" else "FALSE ALARM"


rows = []
for item, result in zip(items, results):
    rows.append({**item, "verdict": result["verdict"], "outcome": outcome(item, result),
                 "source": result["source"], "ai_used": result["ai_used"], "result": result})

if mode != "rules" and not any(r["ai_used"] for r in rows):
    sys.exit("The AI did not run (check keys in .env). Nothing to report.")
ai_failures = sum(1 for r in rows if mode != "rules" and not r["ai_used"])

print(f"Mode: {mode}\n")
print(f"{'id':<10}{'level':<6}{'truth':<7}{'verdict':<15}outcome")
for r in rows:
    flag = "  <--" if r["outcome"] in ("MISSED", "FALSE ALARM", "mild false alarm") else ""
    print(f"{r['id']:<10}{r['difficulty']:<6}{r['label']:<7}{r['verdict']:<15}{r['outcome']}{flag}")


def count(label, difficulty, *outcomes):
    pool = [r for r in rows if r["label"] == label and (difficulty is None or r["difficulty"] == difficulty)]
    return sum(1 for r in pool if r["outcome"] in outcomes), len(pool)


lines = []
def add(text):
    lines.append(text)
    print(text)

print()
add(f"### Accuracy test ({mode}) on 40 messages")
add("")
add("| Group | Result |")
add("|---|---|")
for diff in ("easy", "hard", None):
    name = {"easy": "easy", "hard": "hard", None: "all"}[diff]
    c, n = count("scam", diff, "caught", "caught strongly")
    s, _ = count("scam", diff, "caught strongly")
    add(f"| Scams caught ({name}) | {c}/{n} flagged, {s}/{n} as Likely scam |")
for diff in ("easy", "hard", None):
    name = {"easy": "easy", "hard": "hard", None: "all"}[diff]
    c, n = count("safe", diff, "clean")
    m, _ = count("safe", diff, "mild false alarm")
    f_, _ = count("safe", diff, "FALSE ALARM")
    add(f"| Legitimate left alone ({name}) | {c}/{n} clean, {m} marked Suspicious, {f_} marked Likely scam |")
if ai_failures:
    add("")
    add(f"Note: the AI failed on {ai_failures} message(s), which fell back to rules only.")

print("\n--- Misses and false alarms (what the checker saw) ---")
for r in rows:
    if r["outcome"] in ("MISSED", "FALSE ALARM", "mild false alarm"):
        print(f"\n{r['id']} [{r['outcome']}] ({r['note']})")
        print("  text:   ", r["text"][:110])
        print("  verdict:", r["verdict"], "| rule score:", r["result"]["risk_score"])
        for s in r["result"]["signals"]:
            print("  rule:   ", s["flag"], "<-", s["evidence"])
        if r["result"]["summary"]:
            print("  AI says:", r["result"]["summary"])

with open(f"eval_results_{mode}.md", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print(f"\nSaved eval_results_{mode}.md")