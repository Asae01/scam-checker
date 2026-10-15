"""Look for leaked secrets before you push.   Run:  python check_secrets.py

It checks that:
  1. .env exists only on your computer (ignored by Git, never committed).
  2. No file that Git tracks (or would add with "git add .") contains something that
     looks like an API key or password.
  3. None of the secret values in your local .env appear in your files OR anywhere in
     your Git history (a key you deleted later is still public if it was ever pushed).

It never prints a secret value, only file names, line numbers, variable names and
commit ids. Exit code 0 = clean, 1 = problem found.
"""

import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "Tavily-style key": re.compile(r"tvly-[A-Za-z0-9_\-]{16,}"),
    "Private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Key or password in quotes": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{20,})['"]"""
    ),
    "Key line like KEY=value": re.compile(
        r"(?im)^\s*[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*\s*=\s*['\"]?([A-Za-z0-9_\-./+=]{20,})['\"]?\s*$"
    ),
}
PLACEHOLDER_WORDS = ("your", "paste", "here", "xxxx", "example", "changeme", "placeholder")
SECRET_NAME_RE = re.compile(r"(?i)KEY|SECRET|TOKEN|PASSWORD")
MAX_FILE_BYTES = 1_000_000


def git(*args):
    result = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return result.returncode, result.stdout


def read_text(path):
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def local_secrets():
    """Secret-looking values from your local .env: {variable name: value}."""
    path = Path(".env")
    found = {}
    if not path.exists():
        return found
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name, sep, value = line.partition("=")
        name, value = name.strip(), value.strip().strip("'\"")
        if sep and SECRET_NAME_RE.search(name) and len(value) >= 8:
            found[name] = value
    return found


def main():
    code, _ = git("rev-parse", "--is-inside-work-tree")
    if code != 0:
        print("This folder is not a Git repository. Run the script from your project folder.")
        return 1

    problems = []

    # 1. .env must be untracked and ignored
    _, tracked_out = git("ls-files")
    tracked = tracked_out.splitlines()
    if ".env" in tracked:
        problems.append(".env is tracked by Git. Run: git rm --cached .env  (then rotate the keys inside it)")
    if Path(".env").exists() and git("check-ignore", "-q", ".env")[0] != 0:
        problems.append(".env is not ignored. Add a line  .env  to .gitignore")

    # 2. pattern scan of everything that would be pushed
    _, others_out = git("ls-files", "--others", "--exclude-standard")
    files = sorted(set(tracked) | set(others_out.splitlines()))
    secrets = local_secrets()
    for name in files:
        text = read_text(Path(name))
        if text is None:
            continue
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(1) if match.groups() else match.group(0)
                if any(word in value.lower() for word in PLACEHOLDER_WORDS):
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                problems.append(f"{name}:{line_no}: looks like a secret ({label})")
        for var, value in secrets.items():
            if value in text:
                problems.append(f"{name}: contains the value of {var} from your .env")

    # 3. exact values from your .env anywhere in Git history
    for var, value in secrets.items():
        _, log_out = git("log", "--all", "--oneline", f"-S{value}")
        for line in log_out.splitlines():
            problems.append(f"Git history: the value of {var} appears in commit {line.split()[0]}")

    if problems:
        print("PROBLEMS FOUND (values are never printed):")
        for item in dict.fromkeys(problems):
            print("  -", item)
        print("\nIf a real key was ever pushed, treat it as public: delete it in the provider's "
              "dashboard, create a new one, and put the new one only in .env / Streamlit secrets.")
        return 1

    print("No secrets found in tracked files, new files or Git history.")
    return 0


if __name__ == "__main__":
    sys.exit(main())