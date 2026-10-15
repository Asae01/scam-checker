"""Scam Message Checker: the screen people see.

Run it with:  streamlit run app.py
"""

import html
import json
import logging
import re
from pathlib import Path

import streamlit as st

from scamcheck.domainage import registrable
from scamcheck.highlight import highlight_html
from scamcheck.limits import DailyLimit
from scamcheck.pipeline import MAX_CHARS, analyze
from scamcheck.report import build_report, defang

log = logging.getLogger("scam-checker")

st.set_page_config(
    page_title="Scam Message Checker",
    page_icon="🛡️",
    layout="centered",
    menu_items={
        "About": "Paste a suspicious message to see what looks like a scam and what to do next. "
                 "Built for the Nebius x NVIDIA Global AI Hackathon.",
        "Report a bug": "https://github.com/Asae01/scam-checker/issues",
    },
)

MAX_CHECKS_PER_SESSION = 20  # AI checks per visitor session
MAX_AI_CHECKS_PER_DAY = 150  # AI checks per day across all visitors
SOURCE_URL = "https://github.com/Asae01/scam-checker"

STYLE = """
<style>
.verdict-card {border-radius: 14px; padding: 1.1rem 1.3rem; margin: 0.6rem 0 1.2rem 0;
               border: 1px solid; border-left-width: 10px;}
.verdict-title {font-size: 1.7rem; font-weight: 700; line-height: 1.25; margin: 0;}
.verdict-text {margin: 0.5rem 0 0 0; font-size: 1.02rem; line-height: 1.5;}
.verdict-meta {margin: 0.7rem 0 0 0; font-size: 0.85rem; opacity: 0.75;}
.v-scam {border-color: #dc2626; background: rgba(220, 38, 38, 0.12);}
.v-sus {border-color: #d97706; background: rgba(217, 119, 6, 0.14);}
.v-safe {border-color: #16a34a; background: rgba(22, 163, 74, 0.12);}
</style>
"""

# css class, icon, default sentence. The icon and the words carry the meaning, not just colour.
VERDICTS = {
    "Likely scam": ("v-scam", "🚨", "This message has several signs of a scam. Do not click links, reply, or send anything."),
    "Suspicious": ("v-sus", "⚠️", "Some things look off. Check before you click, reply, or pay."),
    "Probably safe": ("v-safe", "✅", "We found no common scam signs. No check is perfect, so stay careful."),
}

QUICK_EXAMPLES = [
    ("Delivery fee", "scam_01_delivery_fee"),
    ("Code request", "scam_03_otp_request"),
    ("Friend chat", "safe_03_friend_dinner"),
    ("Real login code", "safe_04_real_otp"),
]


@st.cache_data
def load_examples():
    """Read the sample messages so people can try the app in one click."""
    path = Path(__file__).parent / "samples" / "messages.json"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return {item["id"]: item["text"] for item in json.load(f)}


@st.cache_resource
def get_daily_limit():
    return DailyLimit(MAX_AI_CHECKS_PER_DAY)


EXAMPLES = load_examples()


def use_example(example_id):
    st.session_state.message = EXAMPLES[example_id]


def clear_all():
    st.session_state.message = ""
    st.session_state.pop("result", None)
    st.session_state.pop("checked_input", None)


def code_safe(text):
    """Show text as code so it can never become a clickable link."""
    return "`" + str(text).replace("`", "'") + "`"


def plain(text):
    """Make AI-written text safe for markdown: no clickable links, no markup tricks."""
    text = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", str(text))
    text = re.sub(r"(?i)\bwww\.", "www[.]", text)
    return re.sub(r"([\\`*_\[\]()<>#~|])", r"\\\1", text)


def safe_html(text, domains=()):
    """Make untrusted text safe for our own HTML: links defanged, everything escaped."""
    return html.escape(defang(text, domains), quote=True)


def run_check(message):
    """Run one check and remember the result. Never shows technical details to the visitor."""
    # AI and web lookups cost credits, so they have limits. Past a limit the app keeps
    # working with the free rule checks only.
    ai_ok = (
        bool(message.strip())
        and st.session_state.get("ai_checks", 0) < MAX_CHECKS_PER_SESSION
        and get_daily_limit().take()
    )
    try:
        with st.spinner("Checking the message..."):
            result = analyze(message, use_ai=ai_ok)
    except ValueError as error:
        st.warning(str(error))
        return
    except Exception as error:  # never show a stack trace, never log the message
        log.error("check failed: %s", type(error).__name__)
        st.error("Sorry, something went wrong while checking. Please try again in a moment.")
        return

    if ai_ok:
        st.session_state.ai_checks = st.session_state.get("ai_checks", 0) + 1
    result["paused"] = not ai_ok
    st.session_state.result = result
    st.session_state.checked_input = message


def render_result(result):
    facts = result["facts"]
    domains = facts["domains"]

    # 1. The verdict card
    css, icon, default_text = VERDICTS[result["verdict"]]
    text = result["guard_note"] or result["summary"] or default_text
    meta = [f"Confidence: {result['confidence']}"] if result["confidence"] else []
    meta.append("Checked by: " + result["source"])
    st.markdown(
        f'<div class="verdict-card {css}" role="status">'
        f'<p class="verdict-title">{icon} {html.escape(result["verdict"])}</p>'
        f'<p class="verdict-text">{safe_html(text, domains)}</p>'
        f'<p class="verdict-meta">{safe_html(" | ".join(meta), domains)}</p></div>',
        unsafe_allow_html=True,
    )

    # 2. Short notes about how this result was made
    if result.get("paused"):
        st.info("AI analysis and web lookups are paused right now to protect free usage credits. "
                "This result uses the rule checks only.")
    elif result["ai_error"]:
        st.caption("AI analysis was unavailable just now, so this result uses the rule checks only.")
    if result["search_error"]:
        st.caption("Web lookup was unavailable just now.")
    if result["was_truncated"]:
        st.caption(f"The message was long, so only the first {MAX_CHARS} characters were checked.")
    hidden = result["privacy"]["cards_masked"] + result["privacy"]["ids_masked"]
    if hidden:
        st.info(f"We hid {hidden} card or ID number(s) before checking, so they were never sent anywhere.")

    # 3. What to do: always visible, first
    st.subheader("What to do now")
    for step in result["next_steps"]:
        st.markdown("- " + plain(step))

    # 4. Everything else, in tabs
    report = build_report(result)
    labels = ["What stood out"] + (["Report it"] if report else []) + ["Details"]
    tabs = dict(zip(labels, st.tabs(labels)))

    with tabs["What stood out"]:
        if result["ai_used"] and result["red_flags"]:
            for flag in result["red_flags"]:
                line = "- **" + plain(flag["title"]) + "**"
                if flag["explanation"]:
                    line += ": " + plain(flag["explanation"])
                st.markdown(line)
        elif result["signals"]:
            for s in result["signals"]:
                st.markdown(f"- **{s['label']}**: {code_safe(s['evidence'])}")
        else:
            st.write("No common scam red flags were found.")

        marked = highlight_html(result["message"], result["signals"], domains)
        if marked:
            st.caption("Highlighted words matched one of our rule checks. Links are made harmless.")
            st.markdown(marked, unsafe_allow_html=True)
        if result["ai_used"] and result["signals"]:
            with st.expander("Rule checks that fired"):
                for s in result["signals"]:
                    st.markdown(f"- **{s['label']}**: {code_safe(s['evidence'])}")

    if report:
        with tabs["Report it"]:
            st.caption("Copy this and send it to the company being imitated, your bank, or the app where "
                       "it arrived. Links are made harmless so nobody clicks them by accident.")
            st.code(report, language=None)
            st.caption("Also use the report button inside the app you received it in, and look for "
                       "your country's official scam-reporting service.")

    with tabs["Details"]:
        if domains or facts["phones"] or facts["handles"]:
            st.caption("Shown as plain text on purpose. Do not visit these.")
            ages = {a["domain"]: a for a in result["domain_ages"]}
            for domain in domains:
                line = "- Website: " + code_safe(domain)
                age = ages.get(registrable(domain))
                if age:
                    line += f", registered {age['days']} days ago"
                st.markdown(line)
            for phone in facts["phones"]:
                st.markdown("- Phone number: " + code_safe(phone))
            for handle in facts["handles"]:
                st.markdown("- Handle: " + code_safe(handle))
        else:
            st.write("No websites, phone numbers or handles were found in this message.")

        if result["search_results"]:
            st.markdown("**Related warnings from the web (via Tavily)**")
            st.caption("These are search results. They may describe similar scams, not this exact message.")
            for r in result["search_results"]:
                line = "- **" + plain(r["title"] or "Result") + "**"
                if r["snippet"]:
                    line += ": " + plain(r["snippet"])
                st.markdown(line)

        t = result["timing"]
        st.caption(f"Checked in {t['total']} s (lookups {t['lookups']} s, AI {t['ai']} s).")


# ---------------------------------------------------------------- page

st.markdown(STYLE, unsafe_allow_html=True)
st.title("🛡️ Scam Message Checker")
st.write("Got a message that feels off? Paste it below for a quick check: "
         "what looks suspicious, and what to do next.")

available = [(label, ex_id) for label, ex_id in QUICK_EXAMPLES if ex_id in EXAMPLES]
if available:
    st.caption("Not sure what to paste? Try an example:")
    for column, (label, ex_id) in zip(st.columns(len(available)), available):
        column.button(label, key=f"ex_{ex_id}", on_click=use_example, args=(ex_id,))

st.session_state.setdefault("message", "")
message = st.text_area(
    "Paste the message here",
    key="message",
    height=170,
    max_chars=MAX_CHARS,
    placeholder="Example: Your parcel is on hold. Pay a small fee within 24 hours...",
)
st.caption("Please do not paste passwords. Card numbers are hidden automatically before the check.")

check_col, clear_col, _spacer = st.columns([1.2, 1, 2])
check = check_col.button("Check message", type="primary", key="check")
clear_col.button("Clear", key="clear", on_click=clear_all)

if check:
    run_check(message)

result = st.session_state.get("result")
if result:
    if message != st.session_state.get("checked_input"):
        st.info("You changed the message. Press **Check message** to update the result.")
    render_result(result)

st.divider()
with st.expander("How it works and privacy"):
    st.markdown(
        "1. We pick out links, phone numbers and handles. We never open them.\n"
        "2. Rule checks look for 14 classic scam signs.\n"
        "3. We look up how new each website is and what the web says about it, and an AI model "
        "(NVIDIA Nemotron on Nebius Token Factory) reads everything and explains its verdict.\n\n"
        "**Privacy:** this app does not store your message. When AI analysis is on, the message "
        "text is sent to Nebius Token Factory. Websites, phone numbers and handles found in it are "
        "looked up with Tavily, and website names are checked against public domain registration "
        "records (RDAP). Card and ID numbers are hidden before anything is sent."
    )
st.caption(
    "This tool gives a quick estimate, not a guarantee. If you are unsure, contact the company "
    f"using an official website or a number you already trust. [Source code]({SOURCE_URL})"
)