# Attendly

QR-based attendance for colleges (Flask + SQLite).

## Setup

    pip install -r requirements.txt
    python database.py            # creates or updates the database (safe to re-run)
    python create_teacher.py      # create a faculty account
    python app.py                 # http://127.0.0.1:5000

On first start a random secret key is saved to `.secret_key`. Keep that file
private, or set `ATTENDLY_SECRET_KEY` instead.

## Settings (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `ATTENDLY_SECRET_KEY` | auto (`.secret_key`) | Signs sessions and CSRF tokens |
| `ATTENDLY_DEBUG` | off | Werkzeug debugger. Only for your own machine |
| `ATTENDLY_HOST` | 127.0.0.1 | Use 0.0.0.0 to allow phones on the WiFi |
| `ATTENDLY_PORT` | 5000 | Port |
| `ATTENDLY_HTTPS` | off | Serve over HTTPS (phone cameras need it) |
| `ATTENDLY_PUBLIC_URL` | empty | Address written into QR codes and reset emails |
| `ATTENDLY_TRUST_PROXY` | off | Set to 1 behind cloudflared/nginx so real IPs are used |
| `ATTENDLY_SESSION_HOURS` | 8 | Sign-in lasts this long without activity |
| `ATTENDLY_QR_ROTATE_SECONDS` | 30 | How often the attendance QR code changes |
| `ATTENDLY_SMTP_HOST` (+ `_PORT`, `_USER`, `_PASSWORD`, `_FROM`) | empty | Send reset emails; if empty the link prints in the terminal |

## Security features

- Content-Security-Policy with per-request nonces, plus clickjacking, MIME-sniffing and referrer protections
- Session ends when the password changes, so other devices are signed out
- Login lockout per account and per-IP rate limits; reset emails have a 60-second cooldown
- Rotating attendance QR codes: a photo sent to someone absent stops working within about 90 seconds
- CSV export is protected against spreadsheet formula injection

## Folders

- `legacy/` holds old one-time migration and backup scripts, kept for reference only.
