"""Scam Message Checker: the screen people see.

Run it with:  streamlit run app.py
"""

import json
import re
from pathlib import Path

import streamlit as st

from scamcheck.limits import DailyLimit
from scamcheck.pipeline import MAX_CHARS, analyze
from scamcheck.report import build_report

st.set_page_config(page_title="Scam Message Checker", page_icon="🛡️")

NO_EXAMPLE = "(choose an example)"
MAX_CHECKS_PER_SESSION = 20  # AI checks per visitor session
MAX_AI_CHECKS_PER_DAY = 150  # AI checks per day across all visitors


@st.cache_resource
def get_daily_limit():
    return DailyLimit(MAX_AI_CHECKS_PER_DAY)


@st.cache_data
def load_examples():
    """Read the sample messages so people can try the app in one click."""
    path = Path(__file__).parent / "samples" / "messages.json"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        items = json.load(f)
    return {item["id"].replace("_", " "): item["text"] for item in items}


EXAMPLES = load_examples()


def fill_example():
    choice = st.session_state.example_choice
    if choice in EXAMPLES:
        st.session_state.message = EXAMPLES[choice]


def code_safe(text):
    """Show text as code so it can never become a clickable link."""
    return "`" + str(text).replace("`", "'") + "`"


def plain(text):
    """Make AI-written text safe to show: no clickable links, no markdown tricks."""
    text = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", str(text))
    text = re.sub(r"(?i)\bwww\.", "www[.]", text)
    return re.sub(r"([\\`*_\[\]()<>#~|])", r"\\\1", text)


st.title("Scam Message Checker")
st.write(
    "Got a message that feels off? Paste it below and get a quick check: "
    "what looks suspicious, and what to do next."
)

if EXAMPLES:
    st.selectbox(
        "Or try an example",
        [NO_EXAMPLE] + list(EXAMPLES.keys()),
        key="example_choice",
        on_change=fill_example,
    )

message = st.text_area(
    "Paste the message here",
    key="message",
    height=180,
    max_chars=MAX_CHARS,
    placeholder="Example: Your parcel is on hold. Pay a small fee within 24 hours...",
)

if st.button("Check message", type="primary"):
    # AI and web search cost credits, so they have limits. Past a limit the app
    # still works, using the free rule checks only.
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
    else:
        if ai_ok:
            st.session_state.ai_checks = st.session_state.get("ai_checks", 0) + 1
        else:
            st.info(
                "AI analysis and web lookups are paused right now to protect free usage "
                "credits. This result uses the rule checks only."
            )

        verdict = result["verdict"]
        if verdict == "Likely scam":
            st.error("Likely scam")
        elif verdict == "Suspicious":
            st.warning("Suspicious")
        else:
            st.success("Probably safe")

        caption = "Checked by: " + result["source"]
        if result["confidence"]:
            caption += " | Confidence: " + result["confidence"]
        st.caption(caption)

        if result["ai_error"]:
            st.caption("AI analysis was unavailable just now, so this result uses the rule checks only.")
        if result["summary"]:
            st.write(plain(result["summary"]))
        if result["guard_note"]:
            st.info(result["guard_note"])

        st.subheader("Why we think so")
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

        if result["ai_used"] and result["signals"]:
            with st.expander("Rule checks that fired"):
                for s in result["signals"]:
                    st.markdown(f"- **{s['label']}**: {code_safe(s['evidence'])}")

        if result["search_error"]:
            st.caption("Web lookup was unavailable just now.")
        if result["search_results"]:
            with st.expander("Related warnings from the web (via Tavily)"):
                st.caption("These are search results. They may describe similar scams, not this exact message.")
                queries = list(dict.fromkeys(r["query"] for r in result["search_results"]))
                st.caption("Searched for: " + "; ".join(plain(q) for q in queries))
                for r in result["search_results"]:
                    line = "- **" + plain(r["title"] or "Result") + "**"
                    if r["snippet"]:
                        line += ": " + plain(r["snippet"])
                    st.markdown(line)

        st.subheader("What to do next")
        for step in result["next_steps"]:
            st.markdown("- " + plain(step))

        report = build_report(result)
        if report:
            st.subheader("Report it")
            st.caption(
                "Copy this and send it to the company being imitated, your bank, or the app "
                "where it arrived. Links are made harmless so nobody clicks them by accident."
            )
            st.code(report, language=None)
            st.caption(
                "Also use the report button inside the app you received it in, and look for "
                "your country's official scam-reporting service."
            )

        facts = result["facts"]
        if facts["domains"] or facts["phones"] or facts["handles"]:
            st.subheader("Details found in the message")
            st.caption("Shown as plain text on purpose. Do not visit these.")
            for domain in facts["domains"]:
                st.markdown("- Website: " + code_safe(domain))
            for phone in facts["phones"]:
                st.markdown("- Phone number: " + code_safe(phone))
            for handle in facts["handles"]:
                st.markdown("- Handle: " + code_safe(handle))

st.divider()
st.caption(
    "This tool gives a quick estimate, not a guarantee. If you are unsure, "
    "contact the company using an official website or a number you already trust. "
    "This app does not store your message. When AI analysis is on, the message text "
    "is sent to Nebius Token Factory to be analysed, and websites, phone numbers and "
    "handles found in it are looked up with Tavily."
)