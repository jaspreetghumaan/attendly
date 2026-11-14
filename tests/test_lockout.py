import os, sys, tempfile, threading
from datetime import datetime, timedelta
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
os.chdir(PROJECT)

import database
tmpdir = tempfile.mkdtemp()
database.DATABASE_NAME = os.path.join(tmpdir, "test.db")   # never touch the real DB
database.create_tables()

from werkzeug.security import generate_password_hash
import app as appmod
appmod.app.testing = True
client = appmod.app.test_client()

conn = database.get_db_connection()
cur = conn.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
             ("Stu", "stu@x.com", generate_password_hash("RightPass1"), "student"))
conn.execute("INSERT INTO students (user_id, roll_number, course) VALUES (?,?,?)",
             (cur.lastrowid, "R001", "BCA"))
conn.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
             ("Tch", "tch@x.com", generate_password_hash("TeachPass1"), "teacher"))
conn.commit(); conn.close()

appmod._ensure_login_attempts_table()
LOCK_MSG = "Too many wrong attempts"
BAD_MSG = "Invalid email or password."

def login(email, pw, route="/login"):
    r = client.post(route, data={"email": email, "password": pw}, follow_redirects=True)
    return r.get_data(as_text=True)

def logged_in():
    with client.session_transaction() as s:
        return "user_id" in s

def reset_all():
    c = database.get_db_connection(); c.execute("DELETE FROM login_attempts"); c.commit(); c.close()

def set_row(email, **cols):
    c = database.get_db_connection()
    for k, v in cols.items():
        c.execute(f"UPDATE login_attempts SET {k} = ? WHERE email = ?", (v, email))
    c.commit(); c.close()

def clear_session():
    with client.session_transaction() as s:
        s.clear()

# A. wrong password x4 -> still just "invalid"; 5th -> locked
reset_all()
for i in range(4):
    assert BAD_MSG in login("stu@x.com", "wrong"), f"attempt {i+1} should be plain invalid"
assert LOCK_MSG in login("stu@x.com", "wrong"), "5th wrong password must lock"
print("A. 5 wrong passwords -> locked on the 5th")

# B. while locked, the CORRECT password is refused too
assert LOCK_MSG in login("stu@x.com", "RightPass1")
assert not logged_in()
print("B. correct password refused while locked")

# C. lock does not extend when more guesses come in while locked
c = database.get_db_connection()
before = c.execute("SELECT locked_until FROM login_attempts WHERE email='stu@x.com'").fetchone()[0]
c.close()
login("stu@x.com", "wrong"); login("stu@x.com", "wrong")
c = database.get_db_connection()
after = c.execute("SELECT locked_until FROM login_attempts WHERE email='stu@x.com'").fetchone()[0]
c.close()
assert before == after, "guesses during lock must not extend it"
print("C. guesses during lock do not extend the lock")

# D. lock message says roughly 15 minutes
msg = login("stu@x.com", "wrong")
assert "try again in 15 minute(s)" in msg or "try again in 14 minute(s)" in msg, msg
print("D. lock message shows the remaining minutes")

# E. after the 15 minutes pass, the correct password works again
set_row("stu@x.com", locked_until=(datetime.now() - timedelta(seconds=1)).isoformat(timespec="seconds"))
login("stu@x.com", "RightPass1")
assert logged_in(), "login should work after lock expires"
clear_session()
print("E. correct password works again after the lock expires")

# F. a success clears the counter: 4 wrong, 1 right, then 4 wrong -> still not locked
reset_all()
for _ in range(4): login("stu@x.com", "wrong")
login("stu@x.com", "RightPass1"); clear_session()
for _ in range(4):
    assert BAD_MSG in login("stu@x.com", "wrong")
print("F. successful login resets the wrong-password count")

# G. old wrong passwords (older than 15 min) do not add up
reset_all()
for _ in range(4): login("stu@x.com", "wrong")
set_row("stu@x.com", last_failed_at=(datetime.now() - timedelta(minutes=16)).isoformat(timespec="seconds"))
assert BAD_MSG in login("stu@x.com", "wrong"), "stale failures must not count"
print("G. failures older than the 15-minute window start a fresh count")

# H. non-existent email locks the same way (no enumeration by lock message)
reset_all()
for i in range(4):
    assert BAD_MSG in login("ghost@x.com", "wrong")
assert LOCK_MSG in login("ghost@x.com", "wrong"), "unknown email must lock too"
print("H. unknown email gets the same lock after 5 tries")

# I. emails are case-insensitive for the counter
reset_all()
for _ in range(4): login("STU@X.com", "wrong")
assert LOCK_MSG in login("stu@X.COM", "wrong")
print("I. email case does not create a fresh counter")

# J. lock is per email: another account is not affected
reset_all()
for _ in range(5): login("stu@x.com", "wrong")
assert LOCK_MSG in login("stu@x.com", "RightPass1")
msg_t = login("tch@x.com", "TeachPass1", route="/faculty_login")
assert LOCK_MSG not in msg_t, "other account must not be locked"
assert logged_in(), "teacher with correct password should log in"
clear_session()
print("J. lock applies per email only")

# K. the lock is shared by the faculty login page
reset_all()
for _ in range(5): login("tch@x.com", "wrong", route="/faculty_login")
assert LOCK_MSG in login("tch@x.com", "TeachPass1", route="/faculty_login")
print("K. faculty login shares the same lock")

# L. role check still works after a correct password
reset_all()
assert "registered as a teacher" in login("tch@x.com", "TeachPass1")
assert "registered as a student" in login("stu@x.com", "RightPass1", route="/faculty_login")
print("L. role messages still shown after correct password")

# M. parallel wrong guesses cannot skip the limit
reset_all()
results = []
def hit():
    _, err = appmod.attempt_login("stu@x.com", "wrong")
    results.append(err)
threads = [threading.Thread(target=hit) for _ in range(30)]
[t.start() for t in threads]; [t.join() for t in threads]
c = database.get_db_connection()
row = c.execute("SELECT failed_count, locked_until FROM login_attempts WHERE email='stu@x.com'").fetchone()
c.close()
assert row["locked_until"] is not None, "30 parallel guesses must lock the account"
assert sum(1 for e in results if e and LOCK_MSG in e) >= 25
print("M. 30 parallel wrong guesses -> locked, no extra counting")

print("\nALL LOCKOUT TESTS PASSED")
