# Scam Message Checker

Paste a suspicious text, email or chat message and get a quick check: a verdict (**Likely scam**, **Suspicious** or **Probably safe**), the red flags behind it in plain English, and what to do next.

Built solo for the **Nebius x NVIDIA Global AI Hackathon** (track: **Best Apps and Agents**).

- **Live demo:** YOUR-STREAMLIT-APP-LINK-HERE
- **Demo video:** YOUR-YOUTUBE-LINK-HERE

## Why this exists

Scam messages (fake delivery fees, "your account is locked", fake job offers, requests for security codes) hit ordinary people every day, and they are hard to judge in the moment. This app gives a fast second opinion in simple language, so people know what to do before they click or reply.

## How it works

```
message -> extract facts -> rule checks -> Tavily web lookup -> Nemotron judgement -> result
```

1. **Extract facts** (plain Python): pulls out links, phone numbers and social handles. It never opens a link.
2. **Rule checks** (plain Python): 13 red-flag checks such as urgency, requests for security codes, gift cards, secrecy and fake-looking links. Each flag keeps the exact words that triggered it.
3. **Web lookup** (Tavily): searches for the websites, phone numbers and handles found. Only these details are searched, never the whole message.
4. **AI judgement** (NVIDIA Nemotron on Nebius Token Factory): reads the message, the rule findings and the web results, then returns a verdict, a confidence level, reasons and next steps as structured JSON.
5. **Safety net**: if the AI is fooled into saying "Probably safe" while the rules found strong warning signs, the verdict is raised to "Suspicious" and the screen says so.

If the AI or Tavily is unavailable, the app falls back to the rule-based result instead of failing.

## How Nebius and NVIDIA are used

- **NVIDIA Nemotron** (`NVIDIA Nemotron-3-Nano-30B-A3B`) does the final judgement and writes the explanation.
- **Nebius Token Factory** serves the model. The app makes a runtime call to the Token Factory inference API (OpenAI-compatible) on every check, so there are no GPUs or servers to manage.
- **Tavily** (Nebius Builder Program) provides the web lookups.

## Security and privacy choices

- **Prompt-injection defence:** the message is untrusted. It is wrapped in tags, the model is told never to follow instructions inside it, and `<` / `>` are replaced so a message cannot fake a closing tag.
- **No clickable scam links:** details from the message are shown as plain text, and AI or web text is sanitised so links are not clickable.
- **Cost and abuse limits:** messages are cut at 2,000 characters, at most 3 web searches per check, and 20 checks per session.
- **Privacy:** the app does not store messages. When AI is on, the message text goes to Nebius Token Factory, and extracted websites, numbers and handles go to Tavily. This is stated in the app footer.
- **Secrets:** API keys live in `.env` locally and in Streamlit secrets when hosted. They are never in the repo.

## Run it yourself

Requires Python 3.10+.

```bash
git clone https://github.com/Asae01/scam-checker.git
cd scam-checker
python -m venv venv
venv\Scripts\activate          # Windows  (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env         # macOS/Linux: cp .env.example .env
```

Fill in `.env` with your own keys:

- `NEBIUS_API_KEY` and `NEBIUS_MODEL_ID` from Nebius Token Factory (use a Nemotron model ID from the model catalog)
- `TAVILY_API_KEY` from Tavily

Then start the app:

```bash
streamlit run app.py
```

Without any keys the app still works using the rule checks only.

## Tests

The tests run offline with pretend AI and search clients, so they need no keys or credits:

```bash
python run_samples.py      # link, phone and handle extraction
python run_signals.py      # rule checks vs expected flags on 14 sample messages
python run_pipeline.py     # rules-only verdicts on the same messages
python run_llm_tests.py    # AI step: parsing, fallbacks, injection guard
python run_search_tests.py # Tavily step: queries, failures, privacy
```

`python live_check.py` runs sample messages through the real model and Tavily (uses a few credits).

## Project layout

```
app.py              Streamlit screen
scamcheck/
  extract.py        links, phones, handles
  signals.py        rule checks
  search.py         Tavily lookups
  llm.py            Nemotron call, prompt, reply checking
  pipeline.py       runs all steps and combines the result
samples/messages.json   14 test messages (scam, suspicious, safe)
```

## Honest limits

- English only.
- The rules and test set were written by me (14 messages). They are a starting point, not proof it works on all real scams.
- Web results are often about similar scams, not the exact site, so the app labels them as related warnings.
- The AI can be wrong. The verdict is an estimate, not a guarantee.

## What I would do next

Test on many more real-world messages, support more languages, add screenshot input, and measure accuracy properly.

## License

MIT