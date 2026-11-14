# Main application file for the QR Attendance System
import csv
import hashlib
import hmac
import io
import math
import re
import secrets
import smtplib
import sqlite3
import time
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from urllib.parse import urlsplit

import qrcode
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import config
from database import ensure_columns, get_db_connection


app = Flask(__name__)
app.secret_key = config.SECRET_KEY
csrf = CSRFProtect(app)
# Cookie and session settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,            # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",           # browsers do not send it on cross-site POSTs
    SESSION_COOKIE_SECURE=config.USE_HTTPS,  # cookie goes over HTTPS only when the app runs on HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # a login ends after 8 hours
    WTF_CSRF_TIME_LIMIT=None,                # CSRF token lasts as long as the session
    MAX_CONTENT_LENGTH=64 * 1024,            # reject oversized form posts
)

# =========================================================
# HELPERS
# =========================================================

def is_teacher_logged_in():
    return "user_id" in session and session.get("role") == "teacher"


def is_safe_next_url(url):
    """Allow only paths on this site, such as /attend/abc.

    Browsers remove tab and newline characters from inside a URL. So a value
    like a slash, a tab, then another slash would turn into a link to another
    site. Any whitespace, control character or backslash is therefore rejected,
    and so is any URL that has a scheme or a host.
    """
    if not url or len(url) > 512:
        return False
    if any(ch.isspace() or ord(ch) < 32 or ch == "\\" for ch in url):
        return False
    parts = urlsplit(url)
    return (
        url.startswith("/")
        and not url.startswith("//")
        and not parts.scheme
        and not parts.netloc
    )


# =========================================================
# INPUT CHECKS
# =========================================================

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ROLL_NUMBER_PATTERN = re.compile(r"^[A-Za-z0-9/_-]{1,30}$")
SECTION_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,10}$")
SUBJECT_CODE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,20}$")


def password_problem(password):
    """Return a message if the password is too weak, otherwise None.

    Rule: 8 to 128 characters, with at least one letter and at least one number.
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return "Password must be at least 8 characters long."
    if len(password) > PASSWORD_MAX_LENGTH:
        return "Password must be 128 characters or fewer."
    if not any(ch.isalpha() for ch in password) or not any(ch.isdigit() for ch in password):
        return "Password must contain at least one letter and one number."
    return None


def text_ok(text, max_length):
    """True if the text fits the length limit and has no control characters."""
    if len(text) > max_length:
        return False
    return not any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


CSV_FORMULA_START = ("=", "+", "-", "@")


def csv_safe(value):
    """Stop spreadsheet apps from running a cell as a formula.

    A student name such as =HYPERLINK(...) would be executed by Excel when the
    file is opened. A leading apostrophe makes the cell plain text.
    """
    if value is None:
        return ""
    text = str(value)
    if text.lstrip().startswith(CSV_FORMULA_START):
        return "'" + text
    return text


# =========================================================
# SECURITY HEADERS AND CONTENT SECURITY POLICY
# Every inline <script> in a template must have nonce="{{ csp_nonce }}".
# The browser blocks inline scripts that do not have the right nonce.
# =========================================================

@app.before_request
def create_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def inject_csp_nonce():
    return {"csp_nonce": g.get("csp_nonce", "")}


@app.after_request
def set_security_headers(response):
    nonce = g.get("csp_nonce", "")

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        "style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "style-src-attr 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://i.ibb.co; "
        "media-src 'self' blob:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(self), microphone=(), geolocation=(), payment=()"
    )

    if config.USE_HTTPS:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

    # Pages with personal data must not stay in the browser cache, otherwise
    # the Back button after logout can show them again.
    if response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store"

    return response


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# STUDENT REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        # Personal details
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        dob = request.form.get("dob", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("phone", "").strip()
        alternate_phone = request.form.get("alternate_phone", "").strip()

        # Academic details
        roll_number = request.form.get("roll_number", "").strip()
        department = request.form.get("department", "").strip()
        course = request.form.get("course", "").strip()
        specialization = request.form.get("specialization", "").strip()
        year = request.form.get("year", "").strip()
        semester = request.form.get("semester", "").strip()
        admission_year = request.form.get("admission_year", "").strip()
        section = request.form.get("section", "").strip()
        college = request.form.get("college", "").strip()
        residence_type = request.form.get("residence_type", "").strip()

        # Address and guardian details
        address = request.form.get("address", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        pin_code = request.form.get("pin_code", "").strip()
        guardian_name = request.form.get("guardian_name", "").strip()
        guardian_phone = request.form.get("guardian_phone", "").strip()

        # Required field validation
        required_fields = [
            name,
            email,
            password,
            confirm_password,
            phone,
            roll_number,
            department,
            course,
            residence_type
        ]

        if not all(required_fields):
            flash("Please fill in all required fields.")
            return redirect(url_for("register"))

        # Password validation: 8+ characters, with at least one letter and one number
        problem = password_problem(password)
        if problem:
            flash(problem)
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        # Phone validation
        if not phone.isdigit() or len(phone) != 10:
            flash("Enter a valid 10-digit contact number.")
            return redirect(url_for("register"))

        if alternate_phone and (
            not alternate_phone.isdigit()
            or len(alternate_phone) != 10
        ):
            flash("Enter a valid 10-digit alternate number.")
            return redirect(url_for("register"))

        if guardian_phone and (
            not guardian_phone.isdigit()
            or len(guardian_phone) != 10
        ):
            flash("Enter a valid 10-digit guardian number.")
            return redirect(url_for("register"))

        if pin_code and (
            not pin_code.isdigit()
            or len(pin_code) != 6
        ):
            flash("Enter a valid 6-digit PIN code.")
            return redirect(url_for("register"))

        # Length, format and character checks
        if not text_ok(name, 100) or len(name) < 2:
            flash("Enter your full name (2 to 100 characters, no special control characters).")
            return redirect(url_for("register"))

        if len(email) > 254 or not EMAIL_PATTERN.match(email):
            flash("Enter a valid email address.")
            return redirect(url_for("register"))

        if not ROLL_NUMBER_PATTERN.match(roll_number):
            flash("Roll number may contain only letters, digits, /, _ and - (max 30 characters).")
            return redirect(url_for("register"))

        text_limits = [
            ("Department", department, 100),
            ("Course", course, 150),
            ("Specialization", specialization, 100),
            ("Section", section, 10),
            ("College", college, 150),
            ("Address", address, 255),
            ("City", city, 100),
            ("State", state, 100),
            ("Guardian name", guardian_name, 100),
        ]
        for label, value, limit in text_limits:
            if not text_ok(value, limit):
                flash(f"{label} is too long or contains invalid characters.")
                return redirect(url_for("register"))

        if gender and gender not in ("Male", "Female"):
            flash("Please select a valid gender.")
            return redirect(url_for("register"))

        if dob:
            try:
                birth_date = date.fromisoformat(dob)
            except ValueError:
                flash("Enter a valid date of birth.")
                return redirect(url_for("register"))
            if birth_date > date.today():
                flash("Date of birth cannot be in the future.")
                return redirect(url_for("register"))

        # Department and course validation
        department_courses = {
            "Applied Science": [
                "B.Tech Artificial Intelligence (AI)",
                "B.Tech Computer Science Engineering (CSE)",
                "B.Tech Computer Science and Design (CSD)",
                "B.Tech Civil Engineering",
                "B.Tech Mechanical Engineering",
                "Diploma in Computer Science (CS)",
                "Diploma in Electronics and Communication Engineering (ECE)"
            ],
            "Allied Science": ["RMT", "OTT", "BPT"],
            "Pharmacy": ["B.Pharma", "D.Pharma", "Pharm.D"],
            "Computer Science": [
                "B.Tech Artificial Intelligence (AI)",
                "B.Tech Computer Science Engineering (CSE)",
                "B.Tech Computer Science and Design (CSD)",
                "Diploma in Computer Science (CS)"
            ],
            "Law": ["LLB"],
            "Business Administration": ["BBA", "MBA"],
            "Hotel Management": [
                "BHM (Bachelor of Hotel Management)",
                "B.Sc. Hospitality and Hotel Administration",
                "Diploma in Hotel Management",
                "Diploma in Food Production",
                "Diploma in Front Office Operations"
            ],
            "ME/CIVIL/ECE": [
                "B.Tech Mechanical Engineering",
                "B.Tech Civil Engineering",
                "Diploma in Electronics and Communication Engineering (ECE)"
            ],
            "Department of Computer Application": ["BCA", "MCA"]
        }

        if course not in department_courses.get(department, []):
            flash("Please select a valid course for your department.")
            return redirect(url_for("register"))

        if residence_type not in ["Hosteller", "Day Scholar"]:
            flash("Please select a valid residence type.")
            return redirect(url_for("register"))

        # Convert optional numeric fields
        try:
            year = int(year) if year else None
            semester = int(semester) if semester else None
            admission_year = int(admission_year) if admission_year else None

        except ValueError:
            flash("Year, semester, and admission year must be valid numbers.")
            return redirect(url_for("register"))

        if year is not None and not 1 <= year <= 6:
            flash("Year must be between 1 and 6.")
            return redirect(url_for("register"))

        if semester is not None and not 1 <= semester <= 12:
            flash("Semester must be between 1 and 12.")
            return redirect(url_for("register"))

        if admission_year is not None and not 1990 <= admission_year <= date.today().year + 1:
            flash("Enter a valid admission year.")
            return redirect(url_for("register"))

        # Hash password
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()

        try:
            cursor = conn.execute(
                """
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, 'student')
                """,
                (name, email, hashed_password)
            )

            user_id = cursor.lastrowid

            conn.execute(
                """
                INSERT INTO students (
                    user_id,
                    roll_number,
                    course,
                    dob,
                    gender,
                    phone,
                    alternate_phone,
                    department,
                    specialization,
                    year,
                    semester,
                    admission_year,
                    section,
                    college,
                    address,
                    city,
                    state,
                    pin_code,
                    guardian_name,
                    guardian_phone,
                    residence_type
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    user_id,
                    roll_number,
                    course,
                    dob or None,
                    gender or None,
                    phone,
                    alternate_phone or None,
                    department,
                    specialization or None,
                    year,
                    semester,
                    admission_year,
                    section or None,
                    college or None,
                    address or None,
                    city or None,
                    state or None,
                    pin_code or None,
                    guardian_name or None,
                    guardian_phone or None,
                    residence_type
                )
            )

            conn.commit()
            flash("Registration successful! You can now log in.")

        except Exception as error:
            conn.rollback()

            if "UNIQUE constraint failed" in str(error):
                flash("Email or roll number already exists.")
            else:
                app.logger.exception("Registration failed")
                flash("Registration failed. Please try again.")

        finally:
            conn.close()

        return redirect(url_for("register"))

    return render_template("register.html")


# =========================================================
# LOGIN LOCKOUT (brute-force protection)
#
# After MAX_FAILED_LOGINS wrong passwords for one email, that email is
# locked for LOCKOUT_MINUTES. Every typed email is counted, even one with
# no account, and a wrong email takes as long to check as a wrong password.
# So neither the message nor the timing shows whether an account exists.
# =========================================================

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
# A wrong password older than this no longer counts toward the limit.
FAILED_LOGIN_WINDOW_MINUTES = 15
INVALID_LOGIN_MESSAGE = "Invalid email or password."

# Checked when the email does not exist. It is random, so no typed
# password can match it.
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


def _ensure_login_attempts_table():
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                email TEXT PRIMARY KEY,
                failed_count INTEGER NOT NULL DEFAULT 0,
                last_failed_at TEXT,
                locked_until TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _locked_message(locked_until):
    seconds_left = (locked_until - datetime.now()).total_seconds()
    minutes = max(1, math.ceil(seconds_left / 60))
    return f"Too many wrong attempts. Please try again in {minutes} minute(s)."


def _register_attempt(email, succeeded):
    """Record one login attempt. Return when the lock ends, or None if not locked.

    The lock check and the counter update happen in one transaction.
    BEGIN IMMEDIATE takes the database write lock first, so parallel requests
    run one at a time. A request that started before the lock was set still
    sees the lock here, so it cannot clear the lock or add more guesses.
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
                # Still locked: change nothing, not even for a correct password.
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

    Returns (user, error). On success error is None. On failure user is None
    and error is the message to show the person.
    """
    # A blank form or an oversized email is not a guess at a real password,
    # so it is rejected here and does not count toward the lockout.
    if not email or not password:
        return None, "Please enter your email and password."
    if len(email) > 254:
        return None, INVALID_LOGIN_MESSAGE

    _ensure_login_attempts_table()

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    finally:
        conn.close()

    # The hash check always runs, even when the email does not exist.
    # Skipping it would make a wrong email return much faster than a wrong password.
    stored_hash = user["password"] if user is not None else DUMMY_PASSWORD_HASH
    password_ok = check_password_hash(stored_hash, password)
    succeeded = user is not None and password_ok

    locked_until = _register_attempt(email, succeeded)
    if locked_until is not None:
        return None, _locked_message(locked_until)

    if not succeeded:
        return None, INVALID_LOGIN_MESSAGE

    return user, None


# =========================================================
# STUDENT LOGIN
# URL: /login
# Template: login.html
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        next_url = request.form.get("next", "")

        user, error = attempt_login(email, password)

        if error:
            flash(error)
            return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

        if user["role"] != "student":
            flash(
                "This account is registered as a teacher. "
                "Please use Faculty Login."
            )
            return redirect(url_for("login"))

        # New session on every login. Anything from an older session is dropped.
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]

        # If the student came from a QR scan link, send them back to it
        if is_safe_next_url(next_url):
            return redirect(next_url)

        return redirect(url_for("student_dashboard"))

    return render_template("login.html")


# =========================================================
# FACULTY LOGIN
# URL: /faculty_login
# Template: faculty_login.html
# =========================================================

@app.route("/faculty_login", methods=["GET", "POST"])
def faculty_login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user, error = attempt_login(email, password)

        if error:
            flash(error)
            return redirect(url_for("faculty_login"))

        if user["role"] != "teacher":
            flash(
                "This account is registered as a student. "
                "Please use Student Login."
            )
            return redirect(url_for("faculty_login"))

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]

        return redirect(url_for("teacher_dashboard"))

    return render_template("faculty_login.html")


# =========================================================
# STUDENT DASHBOARD
# =========================================================

@app.route("/student/dashboard")
def student_dashboard():

    if (
        "user_id" not in session
        or session.get("role") != "student"
    ):
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        student = conn.execute(
            """
            SELECT
                users.name,
                users.email,
                students.id AS student_id,
                students.roll_number,
                students.course,
                students.department,
                students.specialization,
                students.year,
                students.semester,
                students.section,
                students.residence_type
            FROM users
            JOIN students ON users.id = students.user_id
            WHERE users.id = ?
            """,
            (session["user_id"],)
        ).fetchone()

        if student is None:
            session.clear()
            flash("Student profile not found.")
            return redirect(url_for("login"))

        # Only finished sessions (closed or expired) are counted, so a
        # session that is still running does not lower the percentage.
        now_iso = datetime.now().isoformat(timespec="seconds")

        attendance_stats = conn.execute(
        f"""
        SELECT
            COUNT(*) AS total_classes,
            SUM(CASE WHEN r.status = 'Present' THEN 1 ELSE 0 END) AS classes_attended
        FROM attendance_records r
        JOIN attendance_sessions s ON s.id = r.session_id
        JOIN student_enrollments se ON se.class_id = s.class_id AND se.student_id = r.student_id
        WHERE r.student_id = :student_id AND {FINISHED_SESSION}
        """,
        {"student_id": student["student_id"], "now": now_iso}
        ).fetchone()

        subject_rows = conn.execute(
        f"""
        SELECT sub.subject_name, sub.subject_code,
               COUNT(*) AS total,
               SUM(CASE WHEN r.status = 'Present' THEN 1 ELSE 0 END) AS attended
        FROM attendance_records r
        JOIN attendance_sessions s ON s.id = r.session_id
        JOIN student_enrollments se ON se.class_id = s.class_id AND se.student_id = r.student_id
        JOIN subjects sub ON sub.id = s.subject_id
        WHERE r.student_id = :student_id AND {FINISHED_SESSION}
        GROUP BY sub.id
        ORDER BY sub.subject_name
        """,
        {"student_id": student["student_id"], "now": now_iso}
        ).fetchall()

        subject_cards = []
        for row in subject_rows:
            attended = row["attended"] or 0
            pct = attendance_percent(attended, row["total"])
            subject_cards.append({
                "name": row["subject_name"],
                "code": row["subject_code"],
                "total": row["total"],
                "attended": attended,
                "absent": row["total"] - attended,
                "percent": pct,
                "level": attendance_level(pct, row["total"]),
            })

        attendance_history = conn.execute(
        """
        SELECT s.session_date AS attendance_date, r.status,
               sub.subject_name, sub.subject_code,
               s.start_time, r.marked_at
        FROM attendance_records r
        JOIN attendance_sessions s ON s.id = r.session_id
        JOIN student_enrollments se ON se.class_id = s.class_id AND se.student_id = r.student_id
        JOIN subjects sub ON sub.id = s.subject_id
        WHERE r.student_id = ?
        ORDER BY s.id DESC
        """,
        (student["student_id"],)
        ).fetchall()

        total_classes = attendance_stats["total_classes"] or 0
        classes_attended = attendance_stats["classes_attended"] or 0

        attendance_percentage = (
        round((classes_attended / total_classes) * 100, 1)
        if total_classes > 0
        else 0
        )

        return render_template(
        "student_dashboard.html",
        student=student,
        total_classes=total_classes,
        classes_attended=classes_attended,
        attendance_percentage=attendance_percentage,
        attendance_history=attendance_history,
        subject_cards=subject_cards,
        min_attendance=MIN_ATTENDANCE
        )

    finally:
        conn.close()


# =========================================================
# TEACHER DASHBOARD
# =========================================================

@app.route("/teacher/dashboard")
def teacher_dashboard():

    if (
        "user_id" not in session
        or session.get("role") != "teacher"
    ):
        return redirect(url_for("faculty_login"))

    conn = get_db_connection()

    try:
        teacher = conn.execute(
            """
            SELECT name, email
            FROM users
            WHERE id = ? AND role = 'teacher'
            """,
            (session["user_id"],)
        ).fetchone()

        if teacher is None:
            session.clear()
            flash("Teacher account not found.")
            return redirect(url_for("faculty_login"))

        # Only this teacher's own data: students enrolled in this teacher's classes,
        # and attendance from this teacher's sessions. Other teachers' data is never counted.
        teacher_id = session["user_id"]

        total_students = conn.execute(
            """
            SELECT COUNT(DISTINCT e.student_id)
            FROM student_enrollments e
            JOIN classes c ON c.id = e.class_id
            WHERE c.created_by = ?
            """,
            (teacher_id,),
        ).fetchone()[0]

        total_attendance = conn.execute(
            """
            SELECT COUNT(*)
            FROM attendance_records r
            JOIN attendance_sessions s ON s.id = r.session_id
            JOIN student_enrollments se
                 ON se.class_id = s.class_id AND se.student_id = r.student_id
            WHERE s.teacher_id = ? AND r.status = 'Present'
            """,
            (teacher_id,),
        ).fetchone()[0]

        students = conn.execute(
            """
            SELECT DISTINCT
                users.name,
                users.email,
                students.roll_number,
                students.department,
                students.course,
                students.year,
                students.semester,
                students.residence_type
            FROM student_enrollments e
            JOIN classes c ON c.id = e.class_id
            JOIN students ON students.id = e.student_id
            JOIN users ON users.id = students.user_id
            WHERE c.created_by = ?
            ORDER BY students.roll_number
            """,
            (teacher_id,),
        ).fetchall()

        return render_template(
            "teacher_dashboard.html",
            teacher=teacher,
            total_students=total_students,
            total_attendance=total_attendance,
            students=students
        )

    finally:
        conn.close()


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["POST"])
def logout():

    previous_role = session.get("role")

    session.clear()
    flash("You have been logged out.")

    if previous_role == "teacher":
        return redirect(url_for("faculty_login"))

    return redirect(url_for("login"))


# =========================================================
# TEACHER: CLASSES AND SUBJECTS
# =========================================================

@app.route("/teacher/classes", methods=["GET", "POST"])
def teacher_classes():

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    teacher_id = session["user_id"]
    conn = get_db_connection()

    try:
        if request.method == "POST":
            form_type = request.form.get("form_type")

            if form_type == "class":
                class_name = request.form.get("class_name", "").strip()
                section = request.form.get("section", "").strip().upper()

                if not class_name or not section:
                    flash("Class name and section are required.")
                elif not text_ok(class_name, 60) or not SECTION_PATTERN.match(section):
                    flash("Class name can be up to 60 characters. Section may use letters, digits and - (max 10).")
                else:
                    try:
                        conn.execute(
                            """
                            INSERT INTO classes (class_name, section, created_by)
                            VALUES (?, ?, ?)
                            """,
                            (class_name, section, teacher_id),
                        )
                        conn.commit()
                        flash("Class created successfully.")
                    except sqlite3.IntegrityError:
                        flash("You already have this class and section.")

            elif form_type == "subject":
                subject_name = request.form.get("subject_name", "").strip()
                subject_code = request.form.get("subject_code", "").strip().upper()

                if not subject_name or not subject_code:
                    flash("Subject name and code are required.")
                elif not text_ok(subject_name, 100) or not SUBJECT_CODE_PATTERN.match(subject_code):
                    flash("Subject name can be up to 100 characters. Code may use letters, digits, - and _ (max 20).")
                else:
                    try:
                        conn.execute(
                            """
                            INSERT INTO subjects (subject_name, subject_code, created_by)
                            VALUES (?, ?, ?)
                            """,
                            (subject_name, subject_code, teacher_id),
                        )
                        conn.commit()
                        flash("Subject created successfully.")
                    except sqlite3.IntegrityError:
                        flash("You already have a subject with this code.")

            return redirect(url_for("teacher_classes"))

        classes = conn.execute(
            """
            SELECT c.id, c.class_name, c.section,
                   (SELECT COUNT(*) FROM student_enrollments e
                     WHERE e.class_id = c.id) AS student_count,
                   (SELECT COUNT(*) FROM attendance_sessions s
                     WHERE s.class_id = c.id) AS session_count
            FROM classes c
            WHERE c.created_by = ?
            ORDER BY c.class_name, c.section
            """,
            (teacher_id,),
        ).fetchall()

        subjects = conn.execute(
            """
            SELECT sub.id, sub.subject_name, sub.subject_code,
                   (SELECT COUNT(*) FROM attendance_sessions s
                     WHERE s.subject_id = sub.id) AS session_count
            FROM subjects sub
            WHERE sub.created_by = ?
            ORDER BY sub.subject_name
            """,
            (teacher_id,),
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "teacher_classes.html",
        classes=classes,
        subjects=subjects
    )


# =========================================================
# TEACHER: ENROLL STUDENTS IN CLASSES
# =========================================================


@app.route("/teacher/classes/<int:class_id>/delete", methods=["POST"])
def delete_class(class_id):
    """Delete one of the teacher's classes, but only if it has never had a session.

    A class with sessions keeps its attendance history, so it cannot be deleted.
    Enrollments are removed with the class. Student accounts are kept.
    """
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    conn = get_db_connection()

    try:
        # Only the teacher who created the class may delete it.
        target = conn.execute(
            """
            SELECT id, class_name, section
            FROM classes
            WHERE id = ? AND created_by = ?
            """,
            (class_id, session["user_id"]),
        ).fetchone()

        if target is None:
            flash("Class not found.")
        else:
            session_count = conn.execute(
                "SELECT COUNT(*) FROM attendance_sessions WHERE class_id = ?",
                (class_id,),
            ).fetchone()[0]
            if session_count:
                flash("This class has attendance sessions, so it cannot be deleted. Attendance history is kept.")
            else:
                conn.execute("DELETE FROM classes WHERE id = ?", (class_id,))
                conn.commit()
                flash(f"Class {target['class_name']} - {target['section']} was deleted.")
    finally:
        conn.close()

    return redirect(url_for("teacher_classes"))


@app.route("/teacher/subjects/<int:subject_id>/delete", methods=["POST"])
def delete_subject(subject_id):
    """Delete one of the teacher's subjects, but only if no session uses it."""
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    conn = get_db_connection()
    try:
        target = conn.execute(
            "SELECT id, subject_name, subject_code FROM subjects WHERE id = ? AND created_by = ?",
            (subject_id, session["user_id"]),
        ).fetchone()

        if target is None:
            flash("Subject not found.")
        else:
            session_count = conn.execute(
                "SELECT COUNT(*) FROM attendance_sessions WHERE subject_id = ?",
                (subject_id,),
            ).fetchone()[0]
            if session_count:
                flash("This subject has attendance sessions, so it cannot be deleted. Attendance history is kept.")
            else:
                conn.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))
                conn.commit()
                flash(f"Subject {target['subject_name']} was deleted.")
    finally:
        conn.close()

    return redirect(url_for("teacher_classes"))

@app.route("/teacher/enrollments/remove", methods=["POST"])
def remove_enrollment():
    """Take a student out of one of the teacher's classes.

    The student's account stays. Their old attendance records are kept, but they
    stop counting in this class (reports and the student's dashboard) until the
    student is added back.
    """
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    class_id = request.form.get("class_id", type=int)
    student_id = request.form.get("student_id", type=int)

    conn = get_db_connection()
    try:
        owned_class = conn.execute(
            "SELECT id FROM classes WHERE id = ? AND created_by = ?",
            (class_id, session["user_id"]),
        ).fetchone()
        if not owned_class:
            flash("Please choose one of your own classes.")
            return redirect(url_for("teacher_enrollments"))

        student = conn.execute(
            """
            SELECT u.name
            FROM student_enrollments e
            JOIN students st ON st.id = e.student_id
            JOIN users u ON u.id = st.user_id
            WHERE e.class_id = ? AND e.student_id = ?
            """,
            (class_id, student_id),
        ).fetchone()

        if student:
            conn.execute(
                "DELETE FROM student_enrollments WHERE class_id = ? AND student_id = ?",
                (class_id, student_id),
            )
            conn.commit()
            flash(f"{student['name']} was removed from the class.")
        else:
            flash("Student is not in this class.")
    finally:
        conn.close()

    return redirect(url_for("teacher_enrollments", class_id=class_id))


@app.route("/teacher/enrollments", methods=["GET", "POST"])
def teacher_enrollments():

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    teacher_id = session["user_id"]
    conn = get_db_connection()

    try:
        if request.method == "POST":
            class_id = request.form.get("class_id", type=int)

            owned_class = None
            if class_id:
                owned_class = conn.execute(
                    "SELECT id FROM classes WHERE id = ? AND created_by = ?",
                    (class_id, teacher_id),
                ).fetchone()

            if not owned_class:
                flash("Please choose one of your own classes.")
                return redirect(url_for("teacher_enrollments"))

            added = 0
            for student_id in request.form.getlist("student_ids", type=int):
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO student_enrollments (class_id, student_id)
                    VALUES (?, ?)
                    """,
                    (class_id, student_id),
                )
                added += cursor.rowcount

            conn.commit()
            flash(f"{added} student(s) added to the class.")
            return redirect(url_for("teacher_enrollments", class_id=class_id))

        classes = conn.execute(
            """
            SELECT id, class_name, section
            FROM classes
            WHERE created_by = ?
            ORDER BY class_name, section
            """,
            (teacher_id,),
        ).fetchall()

        selected = None
        students = []
        enrolled = []

        selected_id = request.args.get("class_id", type=int)

        if selected_id:
            selected = conn.execute(
                "SELECT id, class_name, section FROM classes WHERE id = ? AND created_by = ?",
                (selected_id, teacher_id),
            ).fetchone()

        if selected:
            enrolled = conn.execute(
                """
                SELECT s.id AS student_id, s.roll_number, s.course, u.name
                FROM student_enrollments e
                JOIN students s ON s.id = e.student_id
                JOIN users u ON u.id = s.user_id
                WHERE e.class_id = ?
                ORDER BY s.roll_number
                """,
                (selected["id"],),
            ).fetchall()

            students = conn.execute(
                """
                SELECT s.id, s.roll_number, s.course, u.name
                FROM students s
                JOIN users u ON u.id = s.user_id
                WHERE s.id NOT IN (
                    SELECT student_id
                    FROM student_enrollments
                    WHERE class_id = ?
                )
                ORDER BY s.roll_number
                """,
                (selected["id"],),
            ).fetchall()

    finally:
        conn.close()

    return render_template(
        "teacher_enrollments.html",
        classes=classes,
        selected=selected,
        students=students,
        enrolled=enrolled,
    )


# =========================================================
# TEACHER: START ATTENDANCE SESSIONS
# =========================================================

@app.route("/teacher/sessions", methods=["GET", "POST"])
def teacher_sessions():

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    teacher_id = session["user_id"]
    conn = get_db_connection()

    try:
        if request.method == "POST":
            class_id = request.form.get("class_id", type=int)
            subject_id = request.form.get("subject_id", type=int)
            minutes = request.form.get("duration", default=10, type=int)

            if not (1 <= minutes <= 60):
                flash("Session duration must be between 1 and 60 minutes.")
                return redirect(url_for("teacher_sessions"))

            owned_class = None
            if class_id:
                owned_class = conn.execute(
                    "SELECT id FROM classes WHERE id = ? AND created_by = ?",
                    (class_id, teacher_id),
                ).fetchone()

            owned_subject = None
            if subject_id:
                owned_subject = conn.execute(
                    "SELECT id FROM subjects WHERE id = ? AND created_by = ?",
                    (subject_id, teacher_id),
                ).fetchone()

            if not owned_class or not owned_subject:
                flash("Please choose your own class and subject.")
                return redirect(url_for("teacher_sessions"))

            now = datetime.now()
            expires = now + timedelta(minutes=minutes)

            cursor = conn.execute(
                """
                INSERT INTO attendance_sessions
                    (class_id, subject_id, teacher_id, session_date,
                     start_time, expires_at, qr_token, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
                """,
                (
                    class_id,
                    subject_id,
                    teacher_id,
                    now.date().isoformat(),
                    now.isoformat(timespec="seconds"),
                    expires.isoformat(timespec="seconds"),
                    secrets.token_urlsafe(24),
                ),
            )
            session_id = cursor.lastrowid

            # Every enrolled student starts as Absent.
            # The QR scan will change their row to Present.
            cursor = conn.execute(
                """
                INSERT INTO attendance_records (session_id, student_id, status)
                SELECT ?, student_id, 'Absent'
                FROM student_enrollments
                WHERE class_id = ?
                """,
                (session_id, class_id),
            )

            conn.commit()

            if cursor.rowcount == 0:
                flash("Session started, but this class has no students yet.")
            else:
                flash(f"Session started for {cursor.rowcount} student(s). It closes in {minutes} minute(s).")

            return redirect(url_for("teacher_sessions"))

        classes = conn.execute(
            """
            SELECT id, class_name, section
            FROM classes
            WHERE created_by = ?
            ORDER BY class_name, section
            """,
            (teacher_id,),
        ).fetchall()

        subjects = conn.execute(
            """
            SELECT id, subject_name, subject_code
            FROM subjects
            WHERE created_by = ?
            ORDER BY subject_name
            """,
            (teacher_id,),
        ).fetchall()

        sessions = conn.execute(
            """
            SELECT s.id, s.session_date, s.start_time, s.expires_at, s.status,
                   c.class_name, c.section, sub.subject_name
            FROM attendance_sessions s
            JOIN classes c ON c.id = s.class_id
            JOIN subjects sub ON sub.id = s.subject_id
            WHERE s.teacher_id = ?
            ORDER BY s.id DESC
            LIMIT 20
            """,
            (teacher_id,),
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "teacher_sessions.html",
        classes=classes,
        subjects=subjects,
        sessions=sessions,
        # lets the page tell a LIVE session from one that has expired
        now_iso=datetime.now().isoformat(timespec="seconds"),
    )


# =========================================================
# TEACHER: SESSION QR CODE
# =========================================================

def get_owned_session(session_id):
    """Return the session only if it belongs to the logged-in teacher."""
    conn = get_db_connection()
    try:
        return conn.execute(
            """
            SELECT s.id, s.class_id, s.qr_token, s.expires_at, s.status, s.session_date,
                   c.class_name, c.section, sub.subject_name
            FROM attendance_sessions s
            JOIN classes c ON c.id = s.class_id
            JOIN subjects sub ON sub.id = s.subject_id
            WHERE s.id = ? AND s.teacher_id = ?
            """,
            (session_id, session["user_id"]),
        ).fetchone()
    finally:
        conn.close()


def build_scan_url(token, code=None):
    base = config.PUBLIC_BASE_URL or request.host_url.rstrip("/")
    if code:
        return f"{base}/attend/{token}/{code}"
    return f"{base}/attend/{token}"


# =========================================================
# ROTATING QR CODE
# The scan link carries a short code that changes every QR_ROTATE_SECONDS.
# The code is an HMAC of the session token and the time window, made with the
# server secret, so students cannot predict it. A photo of the QR therefore
# stops working after one rotation and cannot be used to mark a friend present.
# =========================================================

def _qr_window(now_ts):
    """Index of the current rotation window. It changes every QR_ROTATE_SECONDS."""
    return int(now_ts // config.QR_ROTATE_SECONDS)


def _qr_code(qr_token, window):
    digest = hmac.new(
        config.SECRET_KEY.encode(),
        f"{qr_token}:{window}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return digest[:12]


def qr_code_is_valid(qr_token, code, now_ts=None):
    """True if the code belongs to the current window (or the previous one, just after a change)."""
    if config.QR_ROTATE_SECONDS <= 0:
        return True  # rotation is off: the plain session link is enough
    if not code:
        return False

    now_ts = time.time() if now_ts is None else now_ts
    window = _qr_window(now_ts)
    if hmac.compare_digest(code, _qr_code(qr_token, window)):
        return True

    # The student may have had the previous code on screen when the QR changed.
    # Accept it only for a few seconds into the new window.
    grace = min(config.QR_GRACE_SECONDS, config.QR_ROTATE_SECONDS / 6)
    into_window = now_ts - window * config.QR_ROTATE_SECONDS
    if into_window < grace:
        return hmac.compare_digest(code, _qr_code(qr_token, window - 1))
    return False


def qr_state(s, now_ts=None):
    """Everything the QR page needs for the current window: image, link and when it changes next."""
    now_ts = time.time() if now_ts is None else now_ts
    rotate = config.QR_ROTATE_SECONDS

    if rotate <= 0:
        return {
            "window": None,
            "link": build_scan_url(s["qr_token"]),
            "image_url": url_for("session_qr_image", session_id=s["id"]),
            "next_at": None,
            "server_ms": int(now_ts * 1000),
        }

    window = _qr_window(now_ts)
    return {
        "window": window,
        "link": build_scan_url(s["qr_token"], _qr_code(s["qr_token"], window)),
        "image_url": url_for("session_qr_image", session_id=s["id"], w=window),
        "next_at": int((window + 1) * rotate * 1000),
        "server_ms": int(now_ts * 1000),
    }


@app.route("/teacher/sessions/<int:session_id>")
def session_qr_page(session_id):

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    conn = get_db_connection()
    try:
        attendance_rows = conn.execute(
            """
            SELECT st.id AS student_id,
                   st.roll_number,
                   u.name,
                   COALESCE(ar.status, 'Absent') AS status,
                   ar.marked_at,
                   ar.marked_by
            FROM student_enrollments se
            JOIN students st ON st.id = se.student_id
            JOIN users u ON u.id = st.user_id
            LEFT JOIN attendance_records ar
                   ON ar.student_id = st.id AND ar.session_id = ?
            WHERE se.class_id = ?
            ORDER BY u.name
            """,
            (s["id"], s["class_id"]),
        ).fetchall()
    finally:
        conn.close()

    present_count = sum(1 for r in attendance_rows if r["status"] == "Present")

    now_iso = datetime.now().isoformat(timespec="seconds")
    is_open = s["status"] == "open" and s["expires_at"] > now_iso

    return render_template(
        "teacher_session_qr.html",
        s=s,
        is_open=is_open,
        qr=qr_state(s),
        state_url=url_for("session_qr_state", session_id=s["id"]),
        rotate_seconds=config.QR_ROTATE_SECONDS,
        extend_minutes=config.SESSION_EXTEND_MINUTES,
        # lets the page show a live countdown
        now_iso=now_iso,
        attendance_rows=attendance_rows,
        present_count=present_count,
        total_students=len(attendance_rows),
    )


@app.route("/teacher/sessions/<int:session_id>/qr.png")
def session_qr_image(session_id):

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    if config.QR_ROTATE_SECONDS > 0:
        # The page asks for a window (?w=). Only the current or the previous one is allowed,
        # so the teacher's screen can never show a code from the future.
        window = _qr_window(time.time())
        requested = request.args.get("w", type=int)
        if requested in (window - 1, window):
            window = requested
        link = build_scan_url(s["qr_token"], _qr_code(s["qr_token"], window))
    else:
        link = build_scan_url(s["qr_token"])

    img = qrcode.make(link)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    response = send_file(buf, mimetype="image/png")
    response.headers["Cache-Control"] = "no-store"  # the code changes, so never cache it
    return response


@app.route("/teacher/sessions/<int:session_id>/qr-state")
def session_qr_state(session_id):
    """Current QR code, scan link and time of the next change. The QR page calls this at each change."""
    if not is_teacher_logged_in():
        return jsonify(error="Please log in again."), 401

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    response = jsonify(qr_state(s))
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/teacher/sessions/<int:session_id>/close", methods=["POST"])
def close_session(session_id):

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            UPDATE attendance_sessions
            SET status = 'closed'
            WHERE id = ? AND teacher_id = ?
            """,
            (session_id, session["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    if cursor.rowcount == 0:
        abort(404)

    flash("Session closed. Students who did not scan stay marked Absent.")
    return redirect(url_for("session_qr_page", session_id=session_id))


@app.route("/teacher/sessions/<int:session_id>/extend", methods=["POST"])
def extend_session(session_id):
    """Add SESSION_EXTEND_MINUTES to a session that is still running."""
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    minutes = config.SESSION_EXTEND_MINUTES
    now_iso = datetime.now().isoformat(timespec="seconds")
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, status, expires_at FROM attendance_sessions WHERE id = ? AND teacher_id = ?",
            (session_id, session["user_id"]),
        ).fetchone()
        if row is None:
            abort(404)

        if row["status"] != "open" or row["expires_at"] <= now_iso:
            flash("This session is no longer running. Reopen it to add time.")
        else:
            new_expiry = datetime.fromisoformat(row["expires_at"]) + timedelta(minutes=minutes)
            conn.execute(
                "UPDATE attendance_sessions SET expires_at = ? WHERE id = ?",
                (new_expiry.isoformat(timespec="seconds"), session_id),
            )
            conn.commit()
            flash(f"Session extended by {minutes} minutes.")
    finally:
        conn.close()

    return redirect(url_for("session_qr_page", session_id=session_id))


@app.route("/teacher/sessions/<int:session_id>/reopen", methods=["POST"])
def reopen_session(session_id):
    """Open a closed or expired session again for SESSION_EXTEND_MINUTES from now."""
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    minutes = config.SESSION_EXTEND_MINUTES
    new_expiry = datetime.now() + timedelta(minutes=minutes)
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            UPDATE attendance_sessions
            SET status = 'open', expires_at = ?
            WHERE id = ? AND teacher_id = ?
            """,
            (new_expiry.isoformat(timespec="seconds"), session_id, session["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    if cursor.rowcount == 0:
        abort(404)

    flash(f"Session reopened for {minutes} minutes. Students can scan again.")
    return redirect(url_for("session_qr_page", session_id=session_id))


@app.route("/teacher/sessions/<int:session_id>/mark", methods=["POST"])
def manual_mark(session_id):
    """Teacher marks one enrolled student Present or Absent by hand.

    Use it when a scan fails or a student forgot their phone. Works while the
    session is running and after it has closed.
    """
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    student_id = request.form.get("student_id", type=int)
    status = request.form.get("status")
    if status not in ("Present", "Absent") or not student_id:
        flash("Choose a student and a status.")
        return redirect(url_for("session_qr_page", session_id=session_id) + "#live")

    conn = get_db_connection()
    try:
        student = conn.execute(
            """
            SELECT u.name
            FROM student_enrollments se
            JOIN students st ON st.id = se.student_id
            JOIN users u ON u.id = st.user_id
            WHERE se.class_id = ? AND st.id = ?
            """,
            (s["class_id"], student_id),
        ).fetchone()

        if student is None:
            flash("This student is not enrolled in this class.")
        else:
            marked_at = datetime.now().isoformat(timespec="seconds") if status == "Present" else None
            conn.execute(
                """
                INSERT INTO attendance_records (session_id, student_id, status, marked_at, marked_by)
                VALUES (?, ?, ?, ?, 'teacher')
                ON CONFLICT (session_id, student_id) DO UPDATE SET
                    status = excluded.status,
                    marked_at = excluded.marked_at,
                    marked_by = excluded.marked_by
                """,
                (session_id, student_id, status, marked_at),
            )
            conn.commit()
            flash(f"{student['name']} marked {status}.")
    finally:
        conn.close()

    return redirect(url_for("session_qr_page", session_id=session_id) + "#live")


@app.route("/teacher/sessions/<int:session_id>/export.csv")
def session_export_csv(session_id):
    """Download one session's attendance as CSV (every enrolled student, with status)."""
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT st.roll_number, u.name,
                   COALESCE(ar.status, 'Absent') AS status,
                   ar.marked_at,
                   ar.marked_by
            FROM student_enrollments se
            JOIN students st ON st.id = se.student_id
            JOIN users u ON u.id = st.user_id
            LEFT JOIN attendance_records ar
                   ON ar.student_id = st.id AND ar.session_id = ?
            WHERE se.class_id = ?
            ORDER BY st.roll_number
            """,
            (s["id"], s["class_id"]),
        ).fetchall()
    finally:
        conn.close()

    marked_by_label = {"student": "Student scan", "teacher": "Teacher"}

    output = io.StringIO()
    output.write("\ufeff")  # BOM, so Excel reads names in Hindi or Punjabi correctly
    writer = csv.writer(output)
    writer.writerow(["Roll number", "Name", "Status", "Marked at", "Marked by"])
    for r in rows:
        writer.writerow([
            csv_safe(r["roll_number"]),
            csv_safe(r["name"]),
            r["status"],
            (r["marked_at"] or "").replace("T", " "),
            marked_by_label.get(r["marked_by"], ""),
        ])

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="attendance-{s["session_date"]}-session-{s["id"]}.csv"'
    )
    return response


# =========================================================
# TEACHER: ATTENDANCE REPORTS
# Class -> list of students -> subject-wise cards for one student.
# Only finished sessions (closed or expired) are counted, so a
# session that is still running does not lower anyone's percentage.
# =========================================================

MIN_ATTENDANCE = 75  # college rule: below this = shortage


def attendance_percent(attended, total):
    return round(attended * 100 / total, 1) if total else 0


def attendance_level(percent, total):
    """Return a CSS colour level for a percentage."""
    if not total:
        return "none"
    if percent >= MIN_ATTENDANCE:
        return "good"
    if percent >= 60:
        return "warn"
    return "low"


# A session counts only after it has finished.
FINISHED_SESSION = "(s.status = 'closed' OR s.expires_at <= :now)"


# Optional subject filter for the reports (used in both SQL and CSV).
SUBJECT_FILTER = "AND (:subject_id IS NULL OR s.subject_id = :subject_id)"


def report_level(percent, total):
    """Teacher-side colour: anything under the minimum is 'low' (a shortage). Used for highlighting."""
    if not total:
        return "none"
    return "good" if percent >= MIN_ATTENDANCE else "low"


@app.route("/teacher/reports")
def teacher_reports():

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    teacher_id = session["user_id"]
    now_iso = datetime.now().isoformat(timespec="seconds")
    conn = get_db_connection()

    try:
        classes = conn.execute(
            """
            SELECT id, class_name, section
            FROM classes
            WHERE created_by = ?
            ORDER BY class_name, section
            """,
            (teacher_id,),
        ).fetchall()

        selected = None
        student_rows = []
        chosen_student = None
        subject_cards = []
        overall = None
        class_sessions = 0
        subject_options = []
        csv_url = None

        class_id = request.args.get("class_id", type=int)
        student_id = request.args.get("student_id", type=int)
        subject_id = request.args.get("subject_id", type=int)

        if class_id:
            selected = conn.execute(
                "SELECT id, class_name, section FROM classes WHERE id = ? AND created_by = ?",
                (class_id, teacher_id),
            ).fetchone()

        if selected:
            # Only subjects that actually have sessions in this class are offered.
            subject_options = conn.execute(
                """
                SELECT DISTINCT sub.id, sub.subject_name, sub.subject_code
                FROM attendance_sessions s
                JOIN subjects sub ON sub.id = s.subject_id
                WHERE s.class_id = ? AND s.teacher_id = ?
                ORDER BY sub.subject_name
                """,
                (selected["id"], teacher_id),
            ).fetchall()
            if subject_id not in {o["id"] for o in subject_options}:
                subject_id = None  # unknown or from another class: show all subjects

            params = {
                "class_id": selected["id"],
                "teacher_id": teacher_id,
                "now": now_iso,
                "subject_id": subject_id,
            }

            csv_args = {"class_id": selected["id"]}
            if subject_id:
                csv_args["subject_id"] = subject_id
            csv_url = url_for("teacher_reports_csv", **csv_args)

            class_sessions = conn.execute(
                f"""
                SELECT COUNT(*) FROM attendance_sessions s
                WHERE s.class_id = :class_id AND s.teacher_id = :teacher_id
                  AND {FINISHED_SESSION} {SUBJECT_FILTER}
                """,
                params,
            ).fetchone()[0]

            rows = conn.execute(
                f"""
                SELECT st.id, st.roll_number, u.name,
                       COUNT(x.status) AS total,
                       COALESCE(SUM(CASE WHEN x.status = 'Present' THEN 1 ELSE 0 END), 0) AS attended
                FROM student_enrollments se
                JOIN students st ON st.id = se.student_id
                JOIN users u ON u.id = st.user_id
                LEFT JOIN (
                    SELECT ar.student_id, ar.status
                    FROM attendance_records ar
                    JOIN attendance_sessions s ON s.id = ar.session_id
                    WHERE s.class_id = :class_id AND s.teacher_id = :teacher_id
                      AND {FINISHED_SESSION} {SUBJECT_FILTER}
                ) x ON x.student_id = st.id
                WHERE se.class_id = :class_id
                GROUP BY st.id
                ORDER BY st.roll_number
                """,
                params,
            ).fetchall()

            for r in rows:
                pct = attendance_percent(r["attended"], r["total"])
                student_rows.append({
                    "id": r["id"],
                    "roll_number": r["roll_number"],
                    "name": r["name"],
                    "total": r["total"],
                    "attended": r["attended"],
                    "absent": r["total"] - r["attended"],
                    "percent": pct,
                    "level": report_level(pct, r["total"]),
                })

            if student_id:
                chosen_student = next(
                    (r for r in student_rows if r["id"] == student_id), None
                )

            if chosen_student:
                cards = conn.execute(
                    f"""
                    SELECT sub.subject_name, sub.subject_code,
                           COUNT(*) AS total,
                           SUM(CASE WHEN ar.status = 'Present' THEN 1 ELSE 0 END) AS attended
                    FROM attendance_records ar
                    JOIN attendance_sessions s ON s.id = ar.session_id
                    JOIN subjects sub ON sub.id = s.subject_id
                    WHERE ar.student_id = :student_id
                      AND s.class_id = :class_id AND s.teacher_id = :teacher_id
                      AND {FINISHED_SESSION} {SUBJECT_FILTER}
                    GROUP BY sub.id
                    ORDER BY sub.subject_name
                    """,
                    dict(params, student_id=chosen_student["id"]),
                ).fetchall()

                for c in cards:
                    attended = c["attended"] or 0
                    pct = attendance_percent(attended, c["total"])
                    subject_cards.append({
                        "name": c["subject_name"],
                        "code": c["subject_code"],
                        "total": c["total"],
                        "attended": attended,
                        "absent": c["total"] - attended,
                        "percent": pct,
                        "level": report_level(pct, c["total"]),
                    })

                overall = chosen_student

    finally:
        conn.close()

    return render_template(
        "teacher_reports.html",
        classes=classes,
        selected=selected,
        student_rows=student_rows,
        class_sessions=class_sessions,
        overall=overall,
        subject_cards=subject_cards,
        subject_options=subject_options,
        subject_id=subject_id,
        csv_url=csv_url,
        min_attendance=MIN_ATTENDANCE,
    )


# =========================================================
# TEACHER: ATTENDANCE REPORTS CSV
# =========================================================

@app.route("/teacher/reports.csv")
def teacher_reports_csv():
    """Download one of this teacher's class reports as CSV (optionally for one subject).

    The numbers match the reports page. Text cells go through csv_safe(), so a
    name such as =HYPERLINK(...) is saved as plain text and not run as a formula.
    """
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    teacher_id = session["user_id"]
    now_iso = datetime.now().isoformat(timespec="seconds")
    class_id = request.args.get("class_id", type=int)
    subject_id = request.args.get("subject_id", type=int)

    conn = get_db_connection()
    try:
        selected = None
        if class_id:
            selected = conn.execute(
                "SELECT id, class_name, section FROM classes WHERE id = ? AND created_by = ?",
                (class_id, teacher_id),
            ).fetchone()

        if selected is None:
            abort(404)

        if subject_id:
            subject = conn.execute(
                """
                SELECT sub.id, sub.subject_name
                FROM subjects sub
                WHERE sub.id = ? AND sub.created_by = ?
                """,
                (subject_id, teacher_id),
            ).fetchone()
            if subject is None:
                abort(404)

        rows = conn.execute(
            f"""
            SELECT st.roll_number, u.name,
                   COUNT(x.status) AS total,
                   COALESCE(SUM(CASE WHEN x.status = 'Present' THEN 1 ELSE 0 END), 0) AS attended
            FROM student_enrollments se
            JOIN students st ON st.id = se.student_id
            JOIN users u ON u.id = st.user_id
            LEFT JOIN (
                SELECT ar.student_id, ar.status
                FROM attendance_records ar
                JOIN attendance_sessions s ON s.id = ar.session_id
                WHERE s.class_id = :class_id AND s.teacher_id = :teacher_id
                  AND {FINISHED_SESSION} {SUBJECT_FILTER}
            ) x ON x.student_id = st.id
            WHERE se.class_id = :class_id
            GROUP BY st.id
            ORDER BY st.roll_number
            """,
            {
                "class_id": selected["id"],
                "teacher_id": teacher_id,
                "now": now_iso,
                "subject_id": subject_id,
            },
        ).fetchall()
    finally:
        conn.close()

    output = io.StringIO()
    output.write("\ufeff")  # BOM, so Excel reads names in Hindi or Punjabi correctly
    writer = csv.writer(output)
    writer.writerow(["Roll number", "Name", "Sessions held", "Attended", "Attendance %"])
    for r in rows:
        writer.writerow([
            csv_safe(r["roll_number"]),
            csv_safe(r["name"]),
            r["total"],
            r["attended"],
            attendance_percent(r["attended"], r["total"]),
        ])

    filename = f"class-{selected['id']}-attendance"
    if subject_id:
        filename += f"-subject-{subject_id}"
    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}.csv"'
    return response


# =========================================================
# STUDENT: SCAN QR AND MARK ATTENDANCE
# =========================================================

@app.route("/attend/<token>")
@app.route("/attend/<token>/<code>")
def mark_attendance(token, code=None):

    # HEAD requests (uptime checks, link previews) must never write attendance.
    # Flask runs the GET code for HEAD, so return before any database write.
    if request.method == "HEAD":
        return "", 200

    if "user_id" not in session or session.get("role") != "student":
        flash("Please log in as a student to mark attendance.")
        return redirect(url_for("login", next=request.path))

    conn = get_db_connection()

    try:
        student = conn.execute(
            "SELECT id FROM students WHERE user_id = ?",
            (session["user_id"],),
        ).fetchone()

        if not student:
            flash("Student profile not found.")
            return redirect(url_for("login"))

        attendance_session = conn.execute(
            """
            SELECT id, class_id, qr_token, status, expires_at
            FROM attendance_sessions
            WHERE qr_token = ?
            """,
            (token,),
        ).fetchone()

        if not attendance_session:
            return render_template(
                "attend_result.html", ok=False,
                message="This QR code is not valid."
            )

        # The QR changes every few seconds. An old photo of it is rejected here.
        if not qr_code_is_valid(attendance_session["qr_token"], code):
            return render_template(
                "attend_result.html", ok=False,
                message="This QR code has expired. Scan the code on the teacher's screen."
            )

        now_iso = datetime.now().isoformat(timespec="seconds")

        if attendance_session["status"] != "open" or attendance_session["expires_at"] <= now_iso:
            return render_template(
                "attend_result.html", ok=False,
                message="This attendance session has closed."
            )

        enrolled = conn.execute(
            """
            SELECT 1 FROM student_enrollments
            WHERE class_id = ? AND student_id = ?
            """,
            (attendance_session["class_id"], student["id"]),
        ).fetchone()

        if not enrolled:
            return render_template(
                "attend_result.html", ok=False,
                message="You are not enrolled in this class."
            )

        record = conn.execute(
            """
            SELECT id, status FROM attendance_records
            WHERE session_id = ? AND student_id = ?
            """,
            (attendance_session["id"], student["id"]),
        ).fetchone()

        if record and record["status"] == "Present":
            return render_template(
                "attend_result.html", ok=True,
                message="Your attendance is already marked for this session."
            )

        if record:
            conn.execute(
                """
                UPDATE attendance_records
                SET status = 'Present', marked_at = ?, marked_by = 'student'
                WHERE id = ?
                """,
                (now_iso, record["id"]),
            )
        else:
            conn.execute(
                """
                INSERT INTO attendance_records (session_id, student_id, status, marked_at, marked_by)
                VALUES (?, ?, 'Present', ?, 'student')
                """,
                (attendance_session["id"], student["id"], now_iso),
            )

        conn.commit()

        return render_template(
            "attend_result.html", ok=True,
            message="Attendance marked as Present."
        )

    finally:
        conn.close()


# ============================================================
# PASSWORD RESET (students and teachers)
# ============================================================

def _ensure_reset_table():
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def send_reset_email(to_email, link):
    """Email the reset link. Without SMTP settings, print it in the terminal."""
    if not config.SMTP_HOST:
        print("\n[PASSWORD RESET] Link for " + to_email + ":\n" + link + "\n", flush=True)
        return
    msg = EmailMessage()
    msg["Subject"] = "Attendly: reset your password"
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        "Use this link to reset your password. It is valid for "
        + str(config.RESET_TOKEN_MINUTES) + " minutes:\n\n" + link +
        "\n\nIf you did not ask for this, you can ignore this email."
    )
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as server:
        server.starttls()
        if config.SMTP_USER:
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
        server.send_message(msg)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    role = request.values.get("role", "student")
    if role not in ("student", "teacher"):
        role = "student"
    back = url_for("faculty_login") if role == "teacher" else url_for("login")
    sent = False

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        _ensure_reset_table()
        conn = get_db_connection()
        try:
            user = conn.execute(
                "SELECT id, email FROM users WHERE email = ?", (email,)
            ).fetchone()
            if user:
                token = secrets.token_urlsafe(32)
                expires = (datetime.now() + timedelta(minutes=config.RESET_TOKEN_MINUTES)).isoformat(timespec="seconds")
                conn.execute(
                    "UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0",
                    (user["id"],),
                )
                conn.execute(
                    "INSERT INTO password_resets (user_id, token_hash, expires_at, used) VALUES (?, ?, ?, 0)",
                    (user["id"], _hash_token(token), expires),
                )
                conn.commit()
                link = url_for("reset_password", token=token, _external=True)
                try:
                    send_reset_email(user["email"], link)
                except Exception as exc:
                    print("[PASSWORD RESET] Email failed:", exc, flush=True)
        finally:
            conn.close()
        # Same answer whether or not the email exists, so people cannot guess accounts
        sent = True

    return render_template("password_reset.html", mode="request", role=role, back=back, sent=sent)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    _ensure_reset_table()
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT pr.id, pr.user_id, pr.expires_at, pr.used, u.role
            FROM password_resets pr
            JOIN users u ON u.id = pr.user_id
            WHERE pr.token_hash = ?
            """,
            (_hash_token(token),),
        ).fetchone()

        now_iso = datetime.now().isoformat(timespec="seconds")
        if row is None or row["used"] != 0 or row["expires_at"] <= now_iso:
            return render_template("password_reset.html", mode="invalid", role="student",
                                   back=url_for("login"))

        back = url_for("faculty_login") if row["role"] == "teacher" else url_for("login")

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            problem = password_problem(password)
            if problem:
                flash(problem)
            elif password != confirm:
                flash("Passwords do not match.")
            else:
                conn.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(password), row["user_id"]),
                )
                conn.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (row["id"],))
                conn.commit()
                flash("Your password has been reset. Please log in with your new password.")
                return redirect(back)

        return render_template("password_reset.html", mode="reset", role=row["role"],
                               back=back, token=token)
    finally:
        conn.close()


# =========================================================
# CHANGE PASSWORD (teachers and students, while logged in)
# =========================================================

@app.route("/change-password", methods=["GET", "POST"])
def change_password():

    if "user_id" not in session or session.get("role") not in ("teacher", "student"):
        return redirect(url_for("login"))

    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        conn = get_db_connection()
        try:
            user = conn.execute(
                "SELECT password FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()

            if user is None:
                session.clear()
                flash("Account not found.")
                return redirect(url_for("login"))

            problem = password_problem(new)
            if not check_password_hash(user["password"], current):
                flash("Your current password is not correct.")
            elif problem:
                flash(problem)
            elif new != confirm:
                flash("The new passwords do not match.")
            elif check_password_hash(user["password"], new):
                flash("Choose a password that is different from your current one.")
            else:
                conn.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(new), session["user_id"]),
                )
                conn.commit()
                flash("Your password has been changed.")
                return redirect(url_for("change_password"))
        finally:
            conn.close()

    back = url_for("teacher_dashboard") if session["role"] == "teacher" else url_for("student_dashboard")
    return render_template("change_password.html", back=back)


# Add newer columns to an existing database on every start (safe to repeat).
def _upgrade_schema():
    conn = get_db_connection()
    try:
        ensure_columns(conn)
        conn.commit()
    finally:
        conn.close()


_upgrade_schema()


if __name__ == "__main__":
    ssl_ctx = "adhoc" if config.USE_HTTPS else None
    app.run(host=config.HOST, debug=config.DEBUG, ssl_context=ssl_ctx)