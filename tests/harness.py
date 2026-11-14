import os, sys, tempfile, re
from datetime import datetime, timedelta

PROJECT = os.environ.get("ATTENDLY_PROJECT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT)
os.chdir(PROJECT)

import database
from werkzeug.security import generate_password_hash
import flask_wtf.csrf as _csrf_mod
import app as appmod

appmod.app.testing = True
# Normal tests post without a CSRF token. CSRF has its own test (test_security.py).
appmod.app.config["WTF_CSRF_ENABLED"] = False
REAL_CSRF = not getattr(_csrf_mod, "IS_STUB", False)
PASSWORDS = {"tch_a@x.com": "TeachA1pass", "tch_b@x.com": "TeachB1pass",
             "s1@x.com": "Stud1pass", "s2@x.com": "Stud2pass"}


def fresh():
    """New empty DB with two teachers, two students, two classes and sessions. Returns ids."""
    database.DATABASE_NAME = os.path.join(tempfile.mkdtemp(), "t.db")
    database.create_tables()
    c = database.get_db_connection()
    now = datetime.now()
    iso = lambda d: d.isoformat(timespec="seconds")

    def user(name, email, pw, role):
        return c.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
                         (name, email, generate_password_hash(pw), role)).lastrowid

    tA = user("Teacher Alpha", "tch_a@x.com", PASSWORDS["tch_a@x.com"], "teacher")
    tB = user("Teacher Beta", "tch_b@x.com", PASSWORDS["tch_b@x.com"], "teacher")
    uS1 = user("Secret Student One", "s1@x.com", PASSWORDS["s1@x.com"], "student")
    uS2 = user("Other Student Two", "s2@x.com", PASSWORDS["s2@x.com"], "student")
    sS1 = c.execute("INSERT INTO students (user_id, roll_number, course, department) VALUES (?,?,?,?)",
                    (uS1, "R-SECRET1", "BCA", "Department of Computer Application")).lastrowid
    sS2 = c.execute("INSERT INTO students (user_id, roll_number, course, department) VALUES (?,?,?,?)",
                    (uS2, "R-OTHER2", "BCA", "Department of Computer Application")).lastrowid
    cA = c.execute("INSERT INTO classes (class_name, section, created_by) VALUES ('ClassA-SECRET','A',?)", (tA,)).lastrowid
    cB = c.execute("INSERT INTO classes (class_name, section, created_by) VALUES ('ClassB-OTHER','B',?)", (tB,)).lastrowid
    subA = c.execute("INSERT INTO subjects (subject_name, subject_code, created_by) VALUES ('SubA-SECRET','SA1',?)", (tA,)).lastrowid
    subB = c.execute("INSERT INTO subjects (subject_name, subject_code, created_by) VALUES ('SubB-OTHER','SB1',?)", (tB,)).lastrowid
    c.execute("INSERT INTO student_enrollments (class_id, student_id) VALUES (?,?)", (cA, sS1))
    c.execute("INSERT INTO student_enrollments (class_id, student_id) VALUES (?,?)", (cB, sS2))

    def sess(class_id, subj, teacher, status, expires, token):
        return c.execute(
            """INSERT INTO attendance_sessions (class_id, subject_id, teacher_id, session_date,
               start_time, expires_at, qr_token, status) VALUES (?,?,?,?,?,?,?,?)""",
            (class_id, subj, teacher, now.date().isoformat(), iso(now - timedelta(hours=1)),
             iso(expires), token, status)).lastrowid

    past = now - timedelta(hours=1)
    future = now + timedelta(minutes=30)
    a1 = sess(cA, subA, tA, "closed", past, None)
    a2 = sess(cA, subA, tA, "closed", past, None)
    aopen = sess(cA, subA, tA, "open", future, "TOKENA")
    b1 = sess(cB, subB, tB, "closed", past, None)
    bopen = sess(cB, subB, tB, "open", future, "TOKENB")

    def rec(session_id, student_id, status):
        c.execute("INSERT INTO attendance_records (session_id, student_id, status) VALUES (?,?,?)",
                  (session_id, student_id, status))

    rec(a1, sS1, "Present"); rec(a2, sS1, "Present"); rec(aopen, sS1, "Absent")
    rec(b1, sS2, "Present"); rec(bopen, sS2, "Absent")
    c.commit(); c.close()
    return dict(tA=tA, tB=tB, uS1=uS1, uS2=uS2, sS1=sS1, sS2=sS2, cA=cA, cB=cB,
                subA=subA, subB=subB, a1=a1, a2=a2, aopen=aopen, b1=b1, bopen=bopen)


def db():
    return database.get_db_connection()


def login(route, email):
    client = appmod.app.test_client()
    client.post(route, data={"email": email, "password": PASSWORDS[email]})
    return client


def count(sql, params=()):
    c = db()
    try:
        return c.execute(sql, params).fetchone()[0]
    finally:
        c.close()


class ScriptAudit:
    """Reads an HTML page and reports inline scripts, their nonces, handlers and <style> tags."""
    def __init__(self, html):
        from html.parser import HTMLParser
        audit = self
        audit.inline_nonces, audit.handlers, audit.style_tags = [], [], 0

        class P(HTMLParser):
            def handle_starttag(self, tag, attrs):
                d = dict(attrs)
                if tag == "script" and "src" not in d:
                    audit.inline_nonces.append(d.get("nonce"))
                if tag == "style":
                    audit.style_tags += 1
                for k in d:
                    if k.startswith("on"):
                        audit.handlers.append((tag, k))
        P().feed(html)


def csp_nonce(response):
    m = re.search(r"'nonce-([^']+)'", response.headers.get("Content-Security-Policy", ""))
    return m.group(1) if m else None
