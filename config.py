import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# DB ka path hamesha project folder ke andar, chahe app kahin se bhi chale
DATABASE_PATH = BASE_DIR / "smartattend.db"

# Secret key session cookies aur CSRF tokens ko sign karti hai. Do tarike se milti hai:
#   1. ATTENDLY_SECRET_KEY environment variable (production mein yahi use karein)
#   2. Warna ek random key, jo project folder mein .secret_key file mein save hoti hai.
#      Pehli baar app chalne par khud ban jaati hai, aur agli baar wahi use hoti hai,
#      taaki restart ke baad bhi login na tootay. Yeh file git mein commit mat karna.
SECRET_KEY_FILE = BASE_DIR / ".secret_key"


def _load_or_create_secret_key():
    """Saved key padho, warna ek random key banakar save karo."""
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text().strip()

    # Pehle temp file mein poori key likho, phir usse asli naam par link karo.
    # Asli file tabhi dikhti hai jab key poori likhi ho. Agar do process ek saath
    # start hon, to sirf ek link jeetega aur dono ko wahi key milegi.
    tmp_path = SECRET_KEY_FILE.with_name(f".secret_key.{os.getpid()}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32))
    try:
        os.link(tmp_path, SECRET_KEY_FILE)
    except FileExistsError:
        pass  # doosri process ne pehle bana di, uski key use karenge
    finally:
        tmp_path.unlink()

    return SECRET_KEY_FILE.read_text().strip()


SECRET_KEY = os.environ.get("ATTENDLY_SECRET_KEY") or _load_or_create_secret_key()

# Debug sirf tab on hoga jab aap ATTENDLY_DEBUG=1 set karo
DEBUG = os.environ.get("ATTENDLY_DEBUG") == "1"
# Address jo QR code mein jayega. Phone se scan ke liye baad mein set karenge.
PUBLIC_BASE_URL = os.environ.get("ATTENDLY_PUBLIC_URL", "").rstrip("/")
# Address jis par server sunega. Normal use: 127.0.0.1 (sirf laptop).
# Phone demo ke time: 0.0.0.0 (WiFi par sab devices).
HOST = os.environ.get("ATTENDLY_HOST", "127.0.0.1")
# ATTENDLY_HTTPS=1 par server HTTPS par chalega (phone camera ke liye zaroori)
USE_HTTPS = os.environ.get("ATTENDLY_HTTPS") == "1"

# Password reset emails. Set these as environment variables.
# If ATTENDLY_SMTP_HOST is empty, the reset link is printed in the terminal instead.
SMTP_HOST = os.environ.get("ATTENDLY_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("ATTENDLY_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("ATTENDLY_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("ATTENDLY_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("ATTENDLY_SMTP_FROM", SMTP_USER)
# How long a reset link stays valid
RESET_TOKEN_MINUTES = 30

def _int_env(name, default):
    """Read a whole-number environment variable. Bad values fall back to the default."""
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


# Rotating QR: the QR code changes every this many seconds, so a photo of it
# stops working soon after. Set ATTENDLY_QR_ROTATE_SECONDS=0 to turn this off.
QR_ROTATE_SECONDS = _int_env("ATTENDLY_QR_ROTATE_SECONDS", 30)
# After a rotation, the previous code still works for this many seconds,
# so a student who scanned just before the change is not rejected.
QR_GRACE_SECONDS = 5
# How many minutes the teacher adds with "+5 min" or "Reopen".
SESSION_EXTEND_MINUTES = 5
