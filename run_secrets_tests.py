"""Tests for check_secrets.py, using throw-away Git repos with FAKE keys."""

import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = str(Path("check_secrets.py").resolve())
if not Path(SCRIPT).exists():
    sys.exit("check_secrets.py is missing from this folder. Copy it into the main project folder, next to app.py.")
FAKE_KEY = "fk-AbCdEfGh1234567890XyZaBcDeF"  # not a real key


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.t", *args],
                   cwd=cwd, check=True, capture_output=True)


def new_repo():
    folder = Path(tempfile.mkdtemp())
    git(folder, "init", "-q")
    (folder / ".gitignore").write_text(".env\n")
    (folder / ".env").write_text(f"NEBIUS_API_KEY={FAKE_KEY}\nNEBIUS_MODEL_ID=some/model\n")
    (folder / "README.md").write_text("hello\n")
    git(folder, "add", ".gitignore", "README.md")
    git(folder, "commit", "-q", "-m", "first")
    return folder


def scan(folder):
    result = subprocess.run([sys.executable, SCRIPT], cwd=folder, capture_output=True, text=True)
    return result.returncode, result.stdout


# 1. A clean repo with an ignored .env passes.
repo = new_repo()
code, out = scan(repo)
assert code == 0 and "No secrets found" in out, out
print("1. Clean repo passes: OK")

# 2. A key written into a source file is caught, and the value is never printed.
(repo / "app.py").write_text(f'API_KEY = "{FAKE_KEY}"\n')
code, out = scan(repo)
assert code == 1 and "app.py:1" in out and FAKE_KEY not in out, out
print("2. Key in a file caught, value not printed: OK")

# 3. Placeholders are not flagged.
(repo / "app.py").write_text('NEBIUS_API_KEY = "paste-your-real-key-here"\n')
code, out = scan(repo)
assert code == 0, out
print("3. Placeholders ignored: OK")

# 4. A key committed and then deleted is still found in history.
(repo / "notes.txt").write_text(f"my key is {FAKE_KEY}\n")
git(repo, "add", "notes.txt")
git(repo, "commit", "-q", "-m", "oops")
(repo / "notes.txt").unlink()
git(repo, "add", "-A")
git(repo, "commit", "-q", "-m", "removed it")
code, out = scan(repo)
assert code == 1 and "Git history" in out and "NEBIUS_API_KEY" in out and FAKE_KEY not in out, out
print("4. Deleted-but-committed key found in history: OK")

# 5. A tracked .env is caught.
repo2 = new_repo()
git(repo2, "add", "-f", ".env")
git(repo2, "commit", "-q", "-m", "bad")
code, out = scan(repo2)
assert code == 1 and ".env is tracked" in out and FAKE_KEY not in out, out
print("5. Tracked .env caught: OK")

# 6. A .env that is not ignored is caught.
repo3 = new_repo()
(repo3 / ".gitignore").write_text("")
git(repo3, "add", ".gitignore")
git(repo3, "commit", "-q", "-m", "oops")
code, out = scan(repo3)
assert code == 1 and "not ignored" in out, out
print("6. Un-ignored .env caught: OK")

print("\nAll secret-scan tests passed.")