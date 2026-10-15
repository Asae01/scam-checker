"""Offline tests for the Tavily step. A pretend Tavily client is used: no key or credits needed."""

import testenv  # noqa: F401  (offline test environment: must come first)
import json
import os
from types import SimpleNamespace

from scamcheck.extract import extract_facts
from scamcheck.pipeline import analyze
from scamcheck.search import build_queries, search_entities


class FakeTavily:
    def __init__(self, fail_on=None, fail_all=False):
        self.calls, self.fail_on, self.fail_all = [], fail_on, fail_all

    def search(self, query, search_depth="basic", max_results=3):
        self.calls.append(query)
        if self.fail_all or (self.fail_on and self.fail_on in query):
            raise TimeoutError("slow")
        return {"results": [
            {"title": "Scam report for " + query, "url": "https://reports.example/1",
             "content": "Many users report this is a scam. " * 30},
        ]}


class FakeLLM:
    def __init__(self, reply):
        self.reply, self.prompt = reply, None
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.prompt = kwargs["messages"][1]["content"]
        msg = SimpleNamespace(content=self.reply)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


MSG = ("Pay the fee at http://dhl-parcel-redelivery.example/pay or call +1 555 010 0199 "
       "or message @quickcashjobs01. My secret diary says hunter2.")

# 1. Queries come only from extracted details, never the full message.
facts = extract_facts(MSG)
queries = build_queries(facts)
assert queries == [
    "is dhl-parcel-redelivery.example a scam",
    "+1 555 010 0199 phone number scam reports",
    "@quickcashjobs01 scam",
], queries
assert not any("hunter2" in q or "secret" in q for q in queries)
print("1. Queries built from details only: OK")

# 2. Cap, shorteners and IP addresses are skipped.
many = extract_facts("see http://a-one.example http://b-two.example http://bit.ly/x http://10.0.0.5/y +1 555 010 0199 @someone99")
q = build_queries(many)
assert len(q) <= 3 and not any("bit.ly" in x or "10.0.0.5" in x for x in q), q
assert build_queries(extract_facts("Are we still on for dinner?")) == []
print("2. Cap and skips work: OK")

# 3. Results are normalised and trimmed.
fake = FakeTavily()
results, error = search_entities(facts, client=fake)
assert error is None and len(results) == 3 and len(fake.calls) == 3
assert all(len(r["snippet"]) <= 300 for r in results)
print("3. Results normalised and trimmed: OK")

# 4. One failing query does not break the others; all failing gives an error.
results, error = search_entities(facts, client=FakeTavily(fail_on="@quickcash"))
assert error is None and len(results) == 2
results, error = search_entities(facts, client=FakeTavily(fail_all=True))
assert results == [] and "TimeoutError" in error
print("4. Partial and total failures handled: OK")

# 5. No key set: no results, quiet error code, no crash. No details: nothing to search.
os.environ["TAVILY_API_KEY"] = ""
assert search_entities(facts) == ([], "not_configured")
assert search_entities(extract_facts("hello there")) == ([], None)
print("5. No key / nothing to search: OK")

# 6. Whole pipeline: search results reach the AI prompt, and the result carries them.
reply = json.dumps({"verdict": "Likely scam", "confidence": "high", "summary": "Reported scam.",
                    "red_flags": [], "next_steps": ["Block it."]})
llm = FakeLLM(reply)
os.environ["NEBIUS_MODEL_ID"] = "test-model"
r = analyze(MSG, client=llm, search_client=FakeTavily())
assert "<web_results>" in llm.prompt and "Scam report for" in llm.prompt
assert r["search_results"] and "web search (Tavily)" in r["source"]
assert llm.prompt.count("<web_results>") == 1
print("6. Search results flow into the AI prompt: OK")

# 7. Search broken: AI still runs, app still gets a result.
r = analyze(MSG, client=FakeLLM(reply), search_client=FakeTavily(fail_all=True))
assert r["ai_used"] and r["search_results"] == [] and "web search failed" in r["search_error"]
print("7. Search failure does not stop the AI: OK")

# 8. use_ai=False never touches Tavily.
spy = FakeTavily()
analyze(MSG, use_ai=False, search_client=spy)
assert spy.calls == []
print("8. Offline mode makes no Tavily calls: OK")

print("\nAll search tests passed.")