"""Live check against the REAL model and Tavily (uses a tiny bit of your credits).

  python live_check.py            -> runs 4 sample messages through the whole pipeline
  python live_check.py raw        -> shows the model's raw reply for one sample (for debugging)
  python live_check.py "text"     -> checks a message you type
Your keys are read from .env and are never printed.
"""

import json
import sys

from scamcheck.extract import extract_facts
from scamcheck.llm import SYSTEM_PROMPT, build_user_prompt, get_client, get_setting, parse_model_json
from scamcheck.pipeline import analyze
from scamcheck.signals import detect_signals

SAMPLE_IDS = [
    "scam_01_delivery_fee",
    "scam_03_otp_request",
    "scam_09_subscription",
    "suspicious_02_cold_sales",
    "safe_04_real_otp",
]

with open("samples/messages.json", encoding="utf-8") as f:
    SAMPLES = {m["id"]: m for m in json.load(f)}


def show(label, text):
    print("=" * 70)
    print(label)
    result = analyze(text)
    print("Verdict:   ", result["verdict"], "| confidence:", result["confidence"])
    print("Source:    ", result["source"])
    if result["ai_error"]:
        print("AI problem:", result["ai_error"])
    if result["search_error"]:
        print("Search problem:", result["search_error"])
    if result["summary"]:
        print("Summary:   ", result["summary"])
    for flag in result["red_flags"]:
        print("  - AI flag:", flag["title"], "|", flag["explanation"])
    for s in result["signals"]:
        print("  - rule:   ", s["flag"], "<-", s["evidence"])
    for r in result["search_results"][:3]:
        print("  - web:    ", r["query"], "->", r["title"][:60])
    if result["guard_note"]:
        print("Guard:     ", result["guard_note"])


def raw_reply(text):
    client = get_client()
    model = get_setting("NEBIUS_MODEL_ID")
    if client is None or not model:
        print("Set NEBIUS_API_KEY and NEBIUS_MODEL_ID in .env first.")
        return
    facts = extract_facts(text)
    prompt = build_user_prompt(text, facts, detect_signals(text, facts))
    response = client.chat.completions.create(
        model=model,
        temperature=0.2,
        max_tokens=1200,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    choice = response.choices[0]
    print("finish_reason:", choice.finish_reason)
    if getattr(response, "usage", None):
        print("tokens used:  ", response.usage.total_tokens)
    thinking = getattr(choice.message, "reasoning_content", None)
    if thinking:
        print("--- separate reasoning field (first 300 chars) ---")
        print(thinking[:300])
    print("--- raw reply ---")
    print(choice.message.content)
    print("--- parsed by our code ---")
    print(json.dumps(parse_model_json(choice.message.content), indent=2))


args = sys.argv[1:]
if args and args[0] == "raw":
    raw_reply(SAMPLES[SAMPLE_IDS[0]]["text"])
elif args:
    show("Your message", " ".join(args))
else:
    for sample_id in SAMPLE_IDS:
        msg = SAMPLES[sample_id]
        show(f"{sample_id} (expected: {msg['label']})", msg["text"])