import json

from scamcheck.extract import (
    extract_facts,
    extract_handles,
    extract_phones,
    extract_urls,
    get_domain,
)

# Part 1: run the extractor on every sample message and print what it found.
with open("samples/messages.json", encoding="utf-8") as f:
    messages = json.load(f)

for msg in messages:
    facts = extract_facts(msg["text"])
    print(f"[{msg['id']}] ({msg['label']})")
    print("   urls:   ", facts["urls"])
    print("   domains:", facts["domains"])
    print("   phones: ", facts["phones"])
    print("   handles:", facts["handles"])

# Part 2: small checks for things the sample messages do not cover.
assert extract_phones("Call us on +1 555 010 0199 today.") == ["+1 555 010 0199"]
assert extract_phones("Text 0123456789 for help.") == ["0123456789"]
assert extract_phones("You owe $2.99 by order #48213.") == []
assert extract_urls("Pay at http://pay-now.example/x.") == ["http://pay-now.example/x"]
assert get_domain("https://Secure-Bank.example/login") == "secure-bank.example"
assert get_domain("www.free-prize.example/win") == "www.free-prize.example"
assert extract_handles("DM @quickcashjobs01 now") == ["@quickcashjobs01"]
assert extract_handles("Mail john@site.example") == []

print("\nAll extra checks passed.")