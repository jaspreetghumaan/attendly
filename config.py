"""Central settings for Attendly.

Every value can be overridden with an environment variable (names are unchanged
from the previous version, so existing setups keep working).
"""
import os
from dotenv import load_dotenv
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# The database always lives in the project folder, wherever the app starts from.
DATABASE_PATH = BASE_DIR / "smartattend.db"

# Database to use.
#   empty  -> the local SQLite file above (the default)
#   postgresql://...  -> an external PostgreSQL database such as Supabase.
# Set ATTENDLY_DATABASE_URL to the connection string from your Supabase dashboard.
# Never put the password in a file you share.
DATABASE_URL = os.environ.get("ATTENDLY_DATABASE_URL", "")

# ---------------------------------------------------------------------------
# Secret key
# Signs session cookies and CSRF tokens. Priority:
#   1. ATTENDLY_SECRET_KEY environment variable (recommended in production)
#   2. A random key saved in .secret_key (created automatically on first run)
# There is no hard-coded fallback any more.
# ---------------------------------------------------------------------------
SECRET_KEY_FILE = BASE_DIR / ".secret_key"


def _load_or_create_secret_key():
    """Read the saved key, or create one safely if it does not exist yet."""
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text().strip()

    # Write the full key to a temp file first, then link it to the real name.
    # Two processes starting together cannot leave a half-written key behind.
    tmp_path = SECRET_KEY_FILE.with_name(f".secret_key.{os.getpid()}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32))
    try:
        os.link(tmp_path, SECRET_KEY_FILE)
    except FileExistsError:
        pass  # another process won the race; use its key
    finally:
        tmp_path.unlink()

    return SECRET_KEY_FILE.read_text().strip()


SECRET_KEY = os.environ.get("ATTENDLY_SECRET_KEY") or _load_or_create_secret_key()

# Debug mode exposes an interactive debugger that can run code. It is OFF unless
# you explicitly set ATTENDLY_DEBUG=1 on your own machine. Never on a shared network.
DEBUG = os.environ.get("ATTENDLY_DEBUG") == "1"

# Address written into the QR code. Set this to the public or LAN URL,
# e.g. https://attendly.example.com or http://192.168.1.20:5000
PUBLIC_BASE_URL = os.environ.get("ATTENDLY_PUBLIC_URL", "").rstrip("/")

# Address the server listens on. 127.0.0.1 = this laptop only.
# 0.0.0.0 = every device on the WiFi (use only on a trusted network).
HOST = os.environ.get("ATTENDLY_HOST", "127.0.0.1")
PORT = int(os.environ.get("ATTENDLY_PORT", "5000"))

# ATTENDLY_HTTPS=1 serves over HTTPS (phone cameras need HTTPS on most browsers).
USE_HTTPS = os.environ.get("ATTENDLY_HTTPS") == "1"

# Behind a reverse proxy or tunnel (cloudflared, nginx) set this to 1 so the
# real visitor IP is used for rate limiting. Leave it at 0 otherwise, because
# client-supplied forwarding headers can be faked.
TRUST_PROXY = os.environ.get("ATTENDLY_TRUST_PROXY") == "1"

# Cookies are sent over HTTPS only when the site is served over HTTPS.
COOKIE_SECURE = USE_HTTPS or PUBLIC_BASE_URL.startswith("https://")

# Logged-in sessions end after this many minutes of inactivity.
SESSION_MINUTES = int(os.environ.get("ATTENDLY_SESSION_MINUTES", "15"))

# ---------------------------------------------------------------------------
# Anti-proxy QR codes
# The QR code changes every QR_ROTATE_SECONDS. A code stays valid for the
# current window plus QR_GRACE_WINDOWS older ones, so a student who starts
# scanning just before a change still succeeds. A photo sent to an absent
# friend stops working within about a minute and a half.
# ---------------------------------------------------------------------------
QR_ROTATE_SECONDS = int(os.environ.get("ATTENDLY_QR_ROTATE_SECONDS", "5"))
# Older codes still accepted. Students need time to scan and log in, so keep this above 0.
QR_GRACE_WINDOWS = int(os.environ.get("ATTENDLY_QR_GRACE_WINDOWS", "4"))

# ---------------------------------------------------------------------------
# Password reset emails
# If ATTENDLY_SMTP_HOST is empty, the reset link is printed in the terminal.
# ---------------------------------------------------------------------------
SMTP_HOST = os.environ.get("ATTENDLY_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("ATTENDLY_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("ATTENDLY_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("ATTENDLY_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("ATTENDLY_SMTP_FROM", SMTP_USER)

# How long a reset link stays valid, and how long to wait before sending another
# reset email to the same account (stops inbox flooding).
RESET_TOKEN_MINUTES = 30
RESET_REQUEST_COOLDOWN_SECONDS = 60

# ---------------------------------------------------------------------------
# Teacher sign-up
# Teachers register at /faculty_register and must type this code. Leave it empty
# to turn teacher sign-up off (create accounts with create_teacher.py instead).
# Share the code only with the teachers who should be able to register.
# ---------------------------------------------------------------------------
TEACHER_SIGNUP_CODE = os.environ.get("ATTENDLY_TEACHER_CODE", "")

# Login attempts allowed per IP address in a 10-minute window. Set generously:
# a whole class on one campus WiFi shares a single public IP. Per-account lockout
# is the main brute-force protection.
LOGIN_IP_LIMIT = 100