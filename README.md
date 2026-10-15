# Scam Message Checker

Paste a suspicious text, email or chat message and get a quick check: a verdict (**Likely scam**, **Suspicious** or **Probably safe**), the red flags behind it in plain English, what to do next, and a ready-to-send report message you can copy.

Built solo for the **Nebius x NVIDIA Global AI Hackathon** (track: **Best Apps and Agents**).

- **Live demo:** YOUR-STREAMLIT-APP-LINK-HERE
- **Demo video:** YOUR-YOUTUBE-LINK-HERE

## Why this exists

Scam messages (fake delivery fees, "your account is locked", fake job offers, requests for security codes) hit ordinary people every day, and they are hard to judge in the moment. This app gives a fast second opinion in simple language, so people know what to do before they click or reply.

## How it works

```
message -> extract facts -> rule checks -> website age + Tavily web lookup -> Nemotron judgement -> result
```

1. **Extract facts** (plain Python): pulls out links, phone numbers and social handles. It never opens a link.
2. **Rule checks** (plain Python): 14 red-flag checks such as urgency, requests for security codes, gift cards, secrecy, fake-looking links, and a link that does not match the company the message claims to be from. Each flag keeps the exact words that triggered it.
3. **Lookups** (Tavily and RDAP): searches the web for the websites, phone numbers and handles found, and checks how recently each website was registered using public domain registration records (RDAP). A brand-new website is a common scam sign. Only these details are looked up, never the whole message, and no website is ever visited.
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
- **Cost and abuse limits:** messages are cut at 2,000 characters, at most 3 web searches per check, 20 AI checks per visitor session and 150 AI checks per day across all visitors. Past a limit the app keeps working with the free rule checks only.
- **Privacy:** the app does not store messages. When AI is on, the message text goes to Nebius Token Factory, extracted websites, numbers and handles go to Tavily, and website names go to the public RDAP service (rdap.org). This is stated in the app footer.
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
python run_signals.py      # rule checks vs expected flags on 16 sample messages
python run_pipeline.py     # rules-only verdicts on the same messages
python run_llm_tests.py    # AI step: parsing, fallbacks, injection guard
python run_search_tests.py # Tavily step: queries, failures, privacy
python run_report_tests.py # report message and daily limit
python run_domain_tests.py # website-age check, including redirect safety
python run_highlight_tests.py # highlighting is escaped and link-safe
```

## False-alarm test on real texts

To check that the rules do not flag ordinary messages, I ran them (rules only, no AI) over the 4,827 normal ("ham") messages in the SMS Spam Collection (Almeida and Gómez Hidalgo, UCI, CC BY 4.0). Before fixing, 99.2% were left alone, 0.8% were marked Suspicious and 1 message was marked Likely scam. The test found a real bug ("you won't" matched the prize rule "you won") and an over-broad secrecy rule; I fixed both. After the fix: [paste your new numbers here].

The remaining false alarms are mostly casual uses of words like "urgent" and "immediately". The collection's spam is mostly older promotional spam, so the spam figure says little about modern scams and I do not use it as a measure.

`python live_check.py` runs sample messages through the real model and Tavily (uses a few credits).

## Project layout

```
app.py              Streamlit screen
scamcheck/
  extract.py        links, phones, handles
  signals.py        rule checks
  domainage.py      website age check (RDAP)
  search.py         Tavily lookups
  llm.py            Nemotron call, prompt, reply checking
  pipeline.py       runs all steps and combines the result
  highlight.py      highlights the words that triggered a rule
  report.py         builds the copy-and-send report message
  limits.py         shared daily limit on AI use
samples/messages.json   16 development test messages
samples/eval_set.json   40 messages for the accuracy test
```

## Honest limits

- English only.
- The rules and test set were written by me (16 messages). They are a starting point, not proof it works on all real scams.
- A new website is not always a scam, and website-age lookups can fail (they are then skipped).
- Web results are often about similar scams, not the exact site, so the app labels them as related warnings.
- The AI can be wrong. The verdict is an estimate, not a guarantee.

## What I would do next

Test on many more real-world messages, support more languages, add screenshot input, and measure accuracy properly.

## Data credit

The false-alarm test uses the SMS Spam Collection by Tiago A. Almeida and José María Gómez Hidalgo, from the UCI Machine Learning Repository (https://doi.org/10.24432/C5CC84), licensed under CC BY 4.0. The data is not included in this repository. Download it from UCI and run `python run_dataset_check.py data/sms+spam+collection.zip`.

## License

MIT