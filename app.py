"""Scam Message Checker: the screen people see.

Run it with:  streamlit run app.py
"""

import json
from pathlib import Path

import streamlit as st

from scamcheck.pipeline import MAX_CHARS, analyze

st.set_page_config(page_title="Scam Message Checker", page_icon="🛡️")

NO_EXAMPLE = "(choose an example)"


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
    try:
        result = analyze(message)
    except ValueError as error:
        st.warning(str(error))
    else:
        verdict = result["verdict"]
        if verdict == "Likely scam":
            st.error("Likely scam")
        elif verdict == "Suspicious":
            st.warning("Suspicious")
        else:
            st.success("Probably safe")
        st.caption("Checked by: " + result["source"])

        st.subheader("Why we think so")
        if result["signals"]:
            for s in result["signals"]:
                st.markdown(f"- **{s['label']}**: {code_safe(s['evidence'])}")
        else:
            st.write("No common scam red flags were found.")

        st.subheader("What to do next")
        for step in result["next_steps"]:
            st.markdown(f"- {step}")

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
    "Your message is checked and not saved by this app."
)