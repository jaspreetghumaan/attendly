import re, sys, subprocess, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h
from werkzeug.security import check_password_hash

results = []

class Skip(Exception):
    pass

def test(fn):
    try:
        fn(); results.append((fn.__name__, "PASS", ""))
    except Skip as e:
        results.append((fn.__name__, "SKIP", str(e)))
    except AssertionError as e:
        results.append((fn.__name__, "FAIL", str(e)[:300]))
    except Exception as e:
        results.append((fn.__name__, "ERROR", repr(e)[:300]))
    return fn

PUBLIC = ["/", "/login", "/faculty_login", "/register", "/forgot-password", "/reset-password/notatoken"]

# ---------- headers and CSP ----------
@test
def security_headers_on_public_pages():
    h.fresh()
    c = h.appmod.app.test_client()
    for p in PUBLIC:
        r = c.get(p)
        csp = r.headers.get("Content-Security-Policy", "")
        assert "frame-ancestors 'none'" in csp, f"{p}: no clickjacking protection in CSP"
        assert "object-src 'none'" in csp and "base-uri 'self'" in csp, p
        assert "default-src 'self'" in csp, p
        assert r.headers.get("X-Frame-Options") == "DENY", p
        assert r.headers.get("X-Content-Type-Options") == "nosniff", p
        assert r.headers.get("Referrer-Policy"), p
        assert "camera=(self)" in r.headers.get("Permissions-Policy", ""), p
        assert r.headers.get("Cache-Control") == "no-store", p

@test
def no_unsafe_inline_for_scripts_and_no_eval():
    h.fresh()
    csp = h.appmod.app.test_client().get("/login").headers["Content-Security-Policy"]
    script_src = re.search(r"script-src ([^;]+)", csp).group(1)
    assert "unsafe-inline" not in script_src and "unsafe-eval" not in script_src, script_src

@test
def hsts_only_when_https():
    h.fresh()
    r = h.appmod.app.test_client().get("/login")
    assert "Strict-Transport-Security" not in r.headers

@test
def nonce_is_fresh_every_request():
    h.fresh()
    c = h.appmod.app.test_client()
    n1 = h.csp_nonce(c.get("/login"))
    n2 = h.csp_nonce(c.get("/login"))
    assert n1 and n2 and n1 != n2 and len(n1) >= 16

@test
def every_inline_script_has_matching_nonce_on_all_pages():
    ids = h.fresh()
    pages = {
        "/login": None, "/faculty_login": None, "/register": None,
        "/forgot-password": None, "/reset-password/bad": None,
        "/student/dashboard": "s1@x.com", "/teacher/dashboard": "tch_a@x.com",
        "/teacher/classes": "tch_a@x.com", "/teacher/enrollments": "tch_a@x.com",
        "/teacher/sessions": "tch_a@x.com", "/teacher/reports": "tch_a@x.com",
        f"/teacher/sessions/{ids['aopen']}": "tch_a@x.com",
    }
    problems = []
    for path, who in pages.items():
        if who is None:
            client = h.appmod.app.test_client()
        else:
            route = "/login" if who.startswith("s") else "/faculty_login"
            client = h.login(route, who)
        r = client.get(path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"
        nonce = h.csp_nonce(r)
        audit = h.ScriptAudit(r.get_data(as_text=True))
        for n in audit.inline_nonces:
            if n != nonce:
                problems.append(f"{path}: inline script nonce {n!r} != header {nonce!r}")
        if audit.handlers:
            problems.append(f"{path}: inline event handlers {audit.handlers}")
        if audit.style_tags:
            problems.append(f"{path}: <style> tags present")
    assert not problems, "\n".join(problems[:8])

@test
def no_bare_inline_script_in_any_template():
    import glob
    bad = []
    for f in glob.glob(os.path.join(h.PROJECT, "templates", "*.html")):
        if "<script>" in open(f, encoding="utf-8").read():
            bad.append(os.path.basename(f))
    assert not bad, f"inline scripts without nonce in: {bad}"


@test
def csrf_is_enforced_on_post():
    if not h.REAL_CSRF:
        raise Skip("real Flask-WTF not installed here")
    h.fresh()
    h.appmod.app.config["WTF_CSRF_ENABLED"] = True
    try:
        c = h.appmod.app.test_client()
        r = c.post("/login", data={"email": "s1@x.com", "password": h.PASSWORDS["s1@x.com"]})
        assert r.status_code == 400, f"POST without CSRF token was accepted ({r.status_code})"
    finally:
        h.appmod.app.config["WTF_CSRF_ENABLED"] = False

# ---------- cookies and session ----------
@test
def session_cookie_flags_after_login():
    h.fresh()
    r = h.appmod.app.test_client().post("/login", data={"email": "s1@x.com", "password": h.PASSWORDS["s1@x.com"]})
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie, cookie
    assert "SameSite=Lax" in cookie, cookie
    assert "Secure" not in cookie, "Secure should only be set when HTTPS is on"
    assert "Expires=" in cookie or "Max-Age=" in cookie, "login session should have a lifetime"

@test
def new_session_on_login_drops_old_data():
    h.fresh()
    c = h.appmod.app.test_client()
    with c.session_transaction() as s:
        s["planted"] = "attacker-value"
        s["role"] = "teacher"
    c.post("/login", data={"email": "s1@x.com", "password": h.PASSWORDS["s1@x.com"]})
    with c.session_transaction() as s:
        assert "planted" not in s, "old session data survived login"
        assert s.get("role") == "student"

@test
def logout_clears_session_and_is_post_only():
    h.fresh()
    c = h.login("/login", "s1@x.com")
    assert c.get("/logout").status_code == 405
    c.post("/logout")
    with c.session_transaction() as s:
        assert "user_id" not in s

@test
def debug_off_by_default_and_app_run_uses_config():
    src = open(os.path.join(h.PROJECT, "app.py"), encoding="utf-8").read()
    assert "debug=True" not in src, "app.run still forces debug=True"
    assert "debug=config.DEBUG" in src
    out = subprocess.run([sys.executable, "-c", "import config; print(config.DEBUG)"],
                         cwd=h.PROJECT, capture_output=True, text=True,
                         env={k: v for k, v in os.environ.items() if k != "ATTENDLY_DEBUG"})
    assert out.stdout.strip() == "False", out.stdout + out.stderr

@test
def https_mode_turns_on_secure_cookie_and_hsts():
    code = (
        "import sys, os, tempfile; import database; "
        "database.DATABASE_NAME=os.path.join(tempfile.mkdtemp(),'x.db'); database.create_tables(); "
        "import app as a; a.app.testing=True; c=a.app.test_client(); "
        "r=c.get('/login'); "
        "print(a.app.config['SESSION_COOKIE_SECURE'], r.headers.get('Strict-Transport-Security'))"
    )
    env = dict(os.environ, ATTENDLY_HTTPS="1")
    out = subprocess.run([sys.executable, "-c", code], cwd=h.PROJECT, capture_output=True, text=True, env=env)
    assert out.stdout.strip().splitlines()[-1] == "True max-age=31536000", out.stdout + out.stderr[-400:]

# ---------- password rule ----------
REG = {"name": "Test Student", "email": "new@x.com", "password": "x", "confirm_password": "x",
       "phone": "9876543210", "roll_number": "R-NEW1", "department": "Department of Computer Application",
       "course": "BCA", "residence_type": "Hosteller"}

def try_register(**over):
    h.fresh()
    data = dict(REG, **over)
    data["confirm_password"] = over.get("confirm_password", data["password"])
    h.appmod.app.test_client().post("/register", data=data)
    return h.count("SELECT COUNT(*) FROM users WHERE email = 'new@x.com'")

@test
def password_under_8_chars_rejected():
    assert try_register(password="abc12ab") == 0

@test
def password_without_number_rejected():
    assert try_register(password="abcdefghi") == 0

@test
def password_without_letter_rejected():
    assert try_register(password="123456789") == 0

@test
def password_over_128_rejected():
    assert try_register(password="a1" * 65) == 0

@test
def valid_password_accepted_and_stored_hashed():
    h.fresh()
    h.appmod.app.test_client().post("/register", data=dict(REG, password="abcdefg1", confirm_password="abcdefg1"))
    row = h.db().execute("SELECT password FROM users WHERE email = 'new@x.com'").fetchone()
    assert row is not None, "valid registration was rejected"
    assert row[0] != "abcdefg1" and check_password_hash(row[0], "abcdefg1")

@test
def reset_password_uses_same_rule():
    ids = h.fresh()
    import io, contextlib
    c = h.appmod.app.test_client()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        c.post("/forgot-password", data={"email": "s1@x.com", "role": "student"})
    m = re.search(r"/reset-password/(\S+)", buf.getvalue())
    assert m, "no reset link printed"
    tok = m.group(1)
    c.post(f"/reset-password/{tok}", data={"password": "onlyletters", "confirm_password": "onlyletters"})
    stored = h.db().execute("SELECT password FROM users WHERE id = ?", (ids["uS1"],)).fetchone()[0]
    assert check_password_hash(stored, h.PASSWORDS["s1@x.com"]), "weak reset password was accepted"
    c.post(f"/reset-password/{tok}", data={"password": "newpass99", "confirm_password": "newpass99"})
    stored = h.db().execute("SELECT password FROM users WHERE id = ?", (ids["uS1"],)).fetchone()[0]
    assert check_password_hash(stored, "newpass99"), "strong reset password was not saved"

# ---------- input validation (register) ----------
@test
def register_rejects_bad_fields():
    bad = [
        dict(name="A"),                                   # too short
        dict(name="Ravi\x07Kumar"),                       # control character
        dict(email="not-an-email"),
        dict(email="a" * 250 + "@x.com"),                 # too long
        dict(roll_number="R 1"),                          # space not allowed
        dict(dob="2030-01-01"),                           # future date
        dict(dob="01/02/2000"),                           # wrong format
        dict(gender="Other"),
        dict(year="9"),
        dict(address="x" * 300),
    ]
    for over in bad:
        assert try_register(**over) == 0, f"accepted bad input {over}"

@test
def register_accepts_good_fields():
    h.fresh()
    h.appmod.app.test_client().post("/register", data=dict(
        REG, password="abcdefg1", confirm_password="abcdefg1", dob="2004-05-10", gender="Male",
        year="2", semester="3", address="Street 1, Muktsar"))
    assert h.count("SELECT COUNT(*) FROM users WHERE email = 'new@x.com'") == 1

@test
def class_and_subject_inputs_validated():
    ids = h.fresh()
    c = h.login("/faculty_login", "tch_a@x.com")
    c.post("/teacher/classes", data={"form_type": "class", "class_name": "C" * 61, "section": "A"})
    c.post("/teacher/classes", data={"form_type": "class", "class_name": "Ok", "section": "A B"})
    c.post("/teacher/classes", data={"form_type": "subject", "subject_name": "Maths", "subject_code": "<x>"})
    assert h.count("SELECT COUNT(*) FROM classes WHERE class_name = 'Ok'") == 0
    assert h.count("SELECT COUNT(*) FROM subjects WHERE subject_code = '<X>'") == 0
    assert h.count("SELECT COUNT(*) FROM classes WHERE created_by = ?", (ids["tA"],)) == 1

# ---------- open redirect ----------
@test
def next_url_check_blocks_offsite_targets():
    h.fresh()
    import app as a
    good = ["/attend/abc123", "/student/dashboard", "/attend/TOKEN-_x"]
    bad = ["//evil.com", "/\\evil.com", "/\t/evil.com", "/\n/evil.com", "/\r/evil.com",
           "https://evil.com", "http:evil.com", "javascript:alert(1)", "", "relative/path",
           "/" + "a" * 600, "/ /evil.com"]
    for u in good:
        assert a.is_safe_next_url(u), f"wrongly blocked {u!r}"
    for u in bad:
        assert not a.is_safe_next_url(u), f"allowed {u!r}"

@test
def login_never_redirects_offsite():
    h.fresh()
    for nxt in ["//evil.com", "/\t/evil.com", "https://evil.com/x"]:
        c = h.appmod.app.test_client()
        r = c.post("/login", data={"email": "s1@x.com", "password": h.PASSWORDS["s1@x.com"], "next": nxt})
        loc = r.headers.get("Location", "")
        assert "evil.com" not in loc, f"next={nxt!r} -> {loc!r}"
        assert loc.endswith("/student/dashboard"), f"next={nxt!r} -> {loc!r}"

# ---------- CSV formula injection ----------
@test
def csv_safe_neutralises_formulas():
    import app as a
    cases = {"=1+1": "'=1+1", "+SUM(A1)": "'+SUM(A1)", "-2+3": "'-2+3", "@cmd": "'@cmd",
             " =x": "' =x", "\t=x": "'\t=x", "Ravi": "Ravi", "": "", None: "", 42: "42"}
    for raw, expected in cases.items():
        assert a.csv_safe(raw) == expected, f"{raw!r} -> {a.csv_safe(raw)!r}"

@test
def csv_export_escapes_malicious_names():
    import csv, io
    ids = h.fresh()
    c = h.db()
    c.execute("UPDATE users SET name = ? WHERE id = ?", ('=HYPERLINK("http://evil.example","x")', ids["uS1"]))
    c.execute("UPDATE students SET roll_number = ? WHERE id = ?", ("+12345", ids["sS1"]))
    c.commit(); c.close()
    r = h.login("/faculty_login", "tch_a@x.com").get(f"/teacher/reports.csv?class_id={ids['cA']}")
    assert r.status_code == 200, r.status_code
    assert r.mimetype == "text/csv"
    assert "attachment" in r.headers.get("Content-Disposition", "")
    body = r.get_data(as_text=True)
    assert body.startswith("\ufeff"), "missing BOM for Excel"
    rows = list(csv.reader(io.StringIO(body.lstrip("\ufeff"))))
    assert rows[0] == ["Roll number", "Name", "Sessions held", "Attended", "Attendance %"], rows[0]
    row = rows[1]
    assert row[0] == "'+12345", row
    assert row[1].startswith("'=HYPERLINK"), row
    assert row[2] == "2" and row[3] == "2" and row[4] == "100.0", row
    for line in body.splitlines():
        assert not re.match(r"^[=+\-@]", line.lstrip("\ufeff")), f"formula at line start: {line}"

@test
def csv_requires_teacher_login():
    ids = h.fresh()
    r = h.appmod.app.test_client().get(f"/teacher/reports.csv?class_id={ids['cA']}")
    assert r.status_code == 302 and "faculty_login" in r.headers["Location"]

@test
def reports_page_links_to_csv():
    ids = h.fresh()
    body = h.login("/faculty_login", "tch_a@x.com").get(f"/teacher/reports?class_id={ids['cA']}").get_data(as_text=True)
    assert f"/teacher/reports.csv?class_id={ids['cA']}" in body

# ---------- HEAD requests and blank logins ----------
@test
def head_on_login_never_counts_as_attempt():
    h.fresh()
    c = h.appmod.app.test_client()
    for _ in range(12):
        assert c.open("/login", method="HEAD").status_code == 200
    h.appmod._ensure_login_attempts_table()
    assert h.count("SELECT COUNT(*) FROM login_attempts") == 0

@test
def blank_login_posts_never_count_or_lock():
    h.fresh()
    c = h.appmod.app.test_client()
    for _ in range(12):
        c.post("/login", data={"email": "", "password": ""})
        c.post("/login", data={"email": "s1@x.com", "password": ""})
    h.appmod._ensure_login_attempts_table()
    assert h.count("SELECT COUNT(*) FROM login_attempts") == 0, "blank posts were counted"
    r = c.post("/login", data={"email": "s1@x.com", "password": h.PASSWORDS["s1@x.com"]}, follow_redirects=True)
    assert "Please enter your email and password" not in r.get_data(as_text=True)
    assert "Too many wrong attempts" not in r.get_data(as_text=True)

@test
def head_on_attend_link_does_not_mark_attendance():
    ids = h.fresh()
    c = h.login("/login", "s1@x.com")
    r = c.open("/attend/TOKENA", method="HEAD")
    assert r.status_code == 200
    st = h.db().execute("SELECT status FROM attendance_records WHERE session_id = ? AND student_id = ?",
                        (ids["aopen"], ids["sS1"])).fetchone()[0]
    assert st == "Absent", f"HEAD marked attendance as {st}"

@test
def get_on_attend_link_still_marks_attendance():
    ids = h.fresh()
    c = h.login("/login", "s1@x.com")
    c.get("/attend/TOKENA")
    st = h.db().execute("SELECT status FROM attendance_records WHERE session_id = ? AND student_id = ?",
                        (ids["aopen"], ids["sS1"])).fetchone()[0]
    assert st == "Present", f"normal scan did not mark attendance ({st})"

for name, status, msg in results:
    print(f"{status:5s} {name}" + (f"  -> {msg}" if msg else ""))
fails = [r for r in results if r[1] not in ("PASS", "SKIP")]
skipped = [r for r in results if r[1] == "SKIP"]
print(f"\n{len(results) - len(fails) - len(skipped)}/{len(results)} passed, {len(skipped)} skipped")
sys.exit(1 if fails else 0)
