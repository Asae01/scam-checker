"""Imported FIRST by every offline test, so the tests can never touch real services.

- Blanks the API keys, so a real .env on your computer is ignored during tests
  (python-dotenv never overwrites a variable that is already set).
- Tells the app not to read hosted secrets (Streamlit secrets).
- Blocks every network connection except to this computer. If a test ever tries to
  reach the internet, it fails loudly instead of quietly using your credits.
"""

import atexit
import os
import socket
import sys

os.environ.update({
    "SCAMCHECK_OFFLINE": "1",
    "NEBIUS_API_KEY": "",
    "NEBIUS_MODEL_ID": "",
    "TAVILY_API_KEY": "",
})

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_LOCAL = ("127.0.0.1", "::1", "localhost", "0.0.0.0")
_blocked_attempts = []


def _is_local(address):
    host = address[0] if isinstance(address, tuple) else address
    return host in _LOCAL


def _guarded_connect(self, address, *args, **kwargs):
    if _is_local(address):
        return _real_connect(self, address, *args, **kwargs)
    _blocked_attempts.append(str(address))
    raise OSError(f"network blocked in offline tests (tried to reach {address})")


def _guarded_connect_ex(self, address, *args, **kwargs):
    if _is_local(address):
        return _real_connect_ex(self, address, *args, **kwargs)
    _blocked_attempts.append(str(address))
    raise OSError(f"network blocked in offline tests (tried to reach {address})")


socket.socket.connect = _guarded_connect
socket.socket.connect_ex = _guarded_connect_ex


def _fail_if_network_was_attempted():
    """The app catches network errors and carries on, so a blocked call would pass silently.
    This makes the whole test run fail instead."""
    if _blocked_attempts:
        print("\nOFFLINE TEST VIOLATION: this test tried to reach the internet: "
              + ", ".join(sorted(set(_blocked_attempts))), file=sys.stderr)
        sys.stderr.flush()
        os._exit(1)


atexit.register(_fail_if_network_was_attempted)