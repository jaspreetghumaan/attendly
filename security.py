"""Security helpers for Attendly.

Covers: security headers and a Content-Security-Policy, per-request nonces for
inline scripts, session revalidation (a password change signs out every other
device), IP rate limiting, and the per-account login lockout.
"""
import hashlib
import hmac
import logging
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from flask import g, flash, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import config
from database import get_db_connection

log = logging.getLogger("attendly.security")

# ---------------------------------------------------------------------------
# Login lockout (per email)
# After MAX_FAILED_LOGINS wrong passwords for one email, that email is locked
# for LOCKOUT_MINUTES. Unknown emails are counted too, and a wrong email costs
# the same time as a wrong password, so neither the message nor the timing shows
# whether an account exists.
# ---------------------------------------------------------------------------
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
FAILED_LOGIN_WINDOW_MINUTES = 15
INVALID_LOGIN_MESSAGE = "Invalid email or password."

# Checked when the email does not exist. It is random, so no typed password matches.
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")


def valid_email(value):
    return bool(value) and len(value) <= 254 and bool(EMAIL_RE.match(value))


# ---------------------------------------------------------------------------
# Rate limiting (in memory, sliding window)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key, limit, window_seconds):
        """Record one hit. Return False when the limit is already reached."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 20000:  # keep memory bounded on a busy server
                self._hits.clear()
            hits = self._hits[key]
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True


limiter = RateLimiter()


def client_ip():
    """Return the visitor's IP address, using forwarding headers only when trusted."""
    if config.TRUST_PROXY:
        forwarded = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def _fingerprint(password_hash):
    """A value that changes whenever the password changes. Stored in the session."""
    return hashlib.sha256(("attendly-session:" + password_hash).encode("utf-8")).hexdigest()


def login_user(user):
    """Start a fresh, signed-in session. Clearing first prevents session fixation."""
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]
    session["pwd"] = _fingerprint(user["password"])


def refresh_password_fingerprint(password_hash):
    """Call after the user changes their own password, so this device stays signed in."""
    session["pwd"] = _fingerprint(password_hash)


def is_teacher_logged_in():
    return "user_id" in session and session.get("role") == "teacher"


def is_student_logged_in():
    return "user_id" in session and session.get("role") == "student"


def is_safe_next_url(url):
    """Allow only local paths like /attend/1/abc. Block other sites."""
    return (
        bool(url)
        and url.startswith("/")
        and not url.startswith("//")
        and "\\" not in url
    )


def _check_session():
    """Sign the user out if their account changed (deleted, role changed, or password reset)."""
    if "user_id" not in session or request.endpoint in (None, "static"):
        return
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT role, password FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
    finally:
        conn.close()

    valid = (
        row is not None
        and row["role"] == session.get("role")
        and hmac.compare_digest(_fingerprint(row["password"]), session.get("pwd", ""))
    )
    if not valid:
        log.info("Session ended for user_id=%s (account changed or removed)", session.get("user_id"))
        session.clear()
        flash("Your session has ended. Please log in again.")


# ---------------------------------------------------------------------------
# Login lockout (database-backed)
# ---------------------------------------------------------------------------
def _locked_message(locked_until):
    seconds_left = (locked_until - datetime.now()).total_seconds()
    minutes = max(1, int(-(-seconds_left // 60)))
    return f"Too many wrong attempts. Please try again in {minutes} minute(s)."


def _register_attempt(email, succeeded):
    """Record one login attempt. Return when the lock ends, or None if not locked.

    BEGIN IMMEDIATE takes the write lock first, so parallel guesses run one at a
    time and a request that started before a lock still sees that lock.
    """
    now = datetime.now()
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT failed_count, last_failed_at, locked_until "
            "FROM login_attempts WHERE email = ?",
            (email,),
        ).fetchone()

        if row is not None and row["locked_until"]:
            locked_until = datetime.fromisoformat(row["locked_until"])
            if locked_until > now:
                conn.commit()
                return locked_until

        if succeeded:
            conn.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
            conn.commit()
            return None

        count = 0
        if row is not None and row["last_failed_at"]:
            last_failed = datetime.fromisoformat(row["last_failed_at"])
            if now - last_failed <= timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES):
                count = row["failed_count"]
        count += 1

        locked_until = None
        if count >= MAX_FAILED_LOGINS:
            locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            count = 0

        conn.execute(
            """
            INSERT OR REPLACE INTO login_attempts
                (email, failed_count, last_failed_at, locked_until)
            VALUES (?, ?, ?, ?)
            """,
            (
                email,
                count,
                now.isoformat(timespec="seconds"),
                locked_until.isoformat(timespec="seconds") if locked_until else None,
            ),
        )
        conn.commit()
        return locked_until

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def attempt_login(email, password):
    """Check an email and password against the lockout rules.

    Returns (user, error). On success error is None.
    """
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()

    # The hash check always runs, so a wrong email takes as long as a wrong password.
    stored_hash = user["password"] if user is not None else DUMMY_PASSWORD_HASH
    password_ok = check_password_hash(stored_hash, password)
    succeeded = user is not None and password_ok

    locked_until = _register_attempt(email, succeeded)
    if locked_until is not None:
        log.warning("Login blocked by lockout (ip=%s)", client_ip())
        return None, _locked_message(locked_until)

    if not succeeded:
        log.info("Failed login (ip=%s)", client_ip())
        return None, INVALID_LOGIN_MESSAGE

    return user, None


# ---------------------------------------------------------------------------
# Headers and the per-request nonce
# ---------------------------------------------------------------------------
def _content_security_policy(nonce):
    return "; ".join([
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net",
        "script-src-attr 'none'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net",
        "font-src 'self' data: https://fonts.gstatic.com",
        "img-src 'self' data: blob: https://i.ibb.co",
        "media-src 'self' blob:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ])


def init_app(app):
    """Register the hooks that apply to every request."""

    app.jinja_env.globals["csp_nonce"] = lambda: g.get("csp_nonce", "")

    @app.before_request
    def _prepare_request():
        g.csp_nonce = secrets.token_urlsafe(16)
        _check_session()

    @app.after_request
    def _add_security_headers(response):
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = _content_security_policy(g.get("csp_nonce", ""))
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=(), payment=(), usb=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        # Pages showing a signed-in user's data must not be kept in browser caches
        # (otherwise the Back button shows them after logout).
        if "user_id" in session and request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response
