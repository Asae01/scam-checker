"""Run every offline test in one go.   Run:  python run_all_tests.py

None of these need API keys, credits or the internet, so they also run on GitHub
(see .github/workflows/tests.yml). Exit code 0 = everything passed.
"""

import subprocess
import sys
import time

SCRIPTS = [
    "run_samples.py",         # extracting links, phones, handles
    "run_signals.py",         # rule checks
    "run_pipeline.py",        # rules-only verdicts
    "run_sanitize_tests.py",  # message cleaning
    "run_llm_tests.py",       # AI step: parsing, fallbacks, injection guard
    "run_search_tests.py",    # Tavily step
    "run_domain_tests.py",    # website-age check
    "run_highlight_tests.py", # highlighting
    "run_report_tests.py",    # report message and daily limit
    "run_app_tests.py",       # the screen
    "run_secrets_tests.py",   # the secret scanner
]

failed = []
for script in SCRIPTS:
    started = time.time()
    try:
        proc = subprocess.run([sys.executable, script], capture_output=True, text=True, timeout=300)
        ok = proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc, ok = None, False
    print(f"{'PASS' if ok else 'FAIL'}  {script:<26}({time.time() - started:.1f} s)")
    if not ok:
        failed.append(script)
        if proc is not None:
            print((proc.stdout or "")[-1500:])
            print((proc.stderr or "")[-1500:])

print()
if failed:
    print("FAILED:", ", ".join(failed))
    sys.exit(1)
print(f"All {len(SCRIPTS)} test files passed.")