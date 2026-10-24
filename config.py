import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# DB ka path hamesha project folder ke andar, chahe app kahin se bhi chale
DATABASE_PATH = BASE_DIR / "smartattend.db"

# Secret key: environment variable se lo. Nahi mili to demo ke liye ek fixed key.
# Production mein kabhi bhi yeh fallback mat use karna.
SECRET_KEY = os.environ.get("ATTENDLY_SECRET_KEY", "dev-only-change-me")

# Debug sirf tab on hoga jab aap ATTENDLY_DEBUG=1 set karo
DEBUG = os.environ.get("ATTENDLY_DEBUG") == "1"
# Address jo QR code mein jayega. Phone se scan ke liye baad mein set karenge.
PUBLIC_BASE_URL = os.environ.get("ATTENDLY_PUBLIC_URL", "").rstrip("/")