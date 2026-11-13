"""Attendly: QR attendance system for colleges (Flask + SQLite)."""
import csv
import hashlib
import hmac
import io
import logging
import re
import secrets
import smtplib
import threading
import time
from datetime import datetime, timedelta
from email.message import EmailMessage

import qrcode
from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

import config
import security
from database import IntegrityError, create_tables, get_db_connection
from security import (
    attempt_login,
    client_ip,
    is_safe_next_url,
    is_student_logged_in,
    is_teacher_logged_in,
    limiter,
    login_user,
    refresh_password_fingerprint,
    valid_email,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("attendly")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,          # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",         # not sent on cross-site POSTs
    SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=config.SESSION_MINUTES),
    WTF_CSRF_TIME_LIMIT=config.SESSION_MINUTES * 60,  # matches the session length
    MAX_CONTENT_LENGTH=64 * 1024,          # reject oversized request bodies
)
csrf = CSRFProtect(app)
security.init_app(app)

# Make sure every table exists (safe to run on every start).
create_tables()

MIN_ATTENDANCE = 75  # college rule: below this = shortage
MIN_PASSWORD = 8
MAX_PASSWORD = 128   # very long passwords only slow down hashing

DEPARTMENT_COURSES = {
    "Applied Science": [
        "B.Tech Artificial Intelligence (AI)",
        "B.Tech Computer Science Engineering (CSE)",
        "B.Tech Computer Science and Design (CSD)",
        "B.Tech Civil Engineering",
        "B.Tech Mechanical Engineering",
        "Diploma in Computer Science (CS)",
        "Diploma in Electronics and Communication Engineering (ECE)",
    ],
    "Allied Science": ["RMT", "OTT", "BPT"],
    "Pharmacy": ["B.Pharma", "D.Pharma", "Pharm.D"],
    "Computer Science": [
        "B.Tech Artificial Intelligence (AI)",
        "B.Tech Computer Science Engineering (CSE)",
        "B.Tech Computer Science and Design (CSD)",
        "Diploma in Computer Science (CS)",
    ],
    "Law": ["LLB"],
    "Business Administration": ["BBA", "MBA"],
    "Hotel Management": [
        "BHM (Bachelor of Hotel Management)",
        "B.Sc. Hospitality and Hotel Administration",
        "Diploma in Hotel Management",
        "Diploma in Food Production",
        "Diploma in Front Office Operations",
    ],
    "ME/CIVIL/ECE": [
        "B.Tech Mechanical Engineering",
        "B.Tech Civil Engineering",
        "Diploma in Electronics and Communication Engineering (ECE)",
    ],
    "Department of Computer Application": ["BCA", "MCA"],
}

# Maximum length of each free-text registration field
MAX_LENGTHS = {
    "name": 100, "roll_number": 30, "course": 120, "specialization": 120,
    "college": 150, "section": 10, "address": 255, "city": 80, "state": 80,
    "guardian_name": 100,
}


# =========================================================
# HELPERS
# =========================================================

# A session counts only after it has finished.
FINISHED_SESSION = "(s.status = 'closed' OR s.expires_at <= :now)"


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


def _fallback_url():
    """Where to send a user when a form expires, based on their role."""
    if is_teacher_logged_in():
        return url_for("teacher_dashboard")
    if is_student_logged_in():
        return url_for("student_dashboard")
    return url_for("home")


def _now_iso():
    return datetime.now().isoformat(timespec="seconds")


def _clean_text(value, max_len):
    """Strip and length-check one form field. Returns (value, ok)."""
    value = (value or "").strip()
    return value, len(value) <= max_len


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """An expired or missing form token: explain and go back, instead of a raw error page."""
    flash("Your form expired. Please try again.")
    return redirect(_fallback_url())


# =========================================================
# QR CODES THAT ROTATE (anti-proxy)
# Each session has a secret token that never leaves the server. The QR shows a
# short code derived from that token and the current time window. Old codes
# stay valid for a few windows so a late scan still works.
# =========================================================

def _qr_window(ts=None):
    return int((time.time() if ts is None else ts) // config.QR_ROTATE_SECONDS)


def _qr_code_for_window(token, window):
    digest = hmac.new(token.encode("utf-8"), str(window).encode("ascii"), hashlib.sha256)
    return digest.hexdigest()[:16]


def current_qr_code(token):
    return _qr_code_for_window(token, _qr_window())


def qr_code_is_valid(token, code):
    """True if the code belongs to the current or a recent time window."""
    if not code or len(code) > 64 or not code.isascii():
        return False
    window = _qr_window()
    for back in range(config.QR_GRACE_WINDOWS + 1):
        if hmac.compare_digest(_qr_code_for_window(token, window - back), code):
            return True
    return False


def build_scan_url(session_id, code):
    base = config.PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return f"{base}/attend/{session_id}/{code}"


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

        form = request.form
        name = form.get("name", "").strip()
        email = form.get("email", "").strip().lower()
        password = form.get("password", "")
        confirm_password = form.get("confirm_password", "")

        dob = form.get("dob", "").strip()
        gender = form.get("gender", "").strip()
        phone = form.get("phone", "").strip()
        alternate_phone = form.get("alternate_phone", "").strip()

        roll_number = form.get("roll_number", "").strip()
        department = form.get("department", "").strip()
        course = form.get("course", "").strip()
        specialization = form.get("specialization", "").strip()
        year = form.get("year", "").strip()
        semester = form.get("semester", "").strip()
        admission_year = form.get("admission_year", "").strip()
        section = form.get("section", "").strip()
        college = form.get("college", "").strip()
        residence_type = form.get("residence_type", "").strip()

        address = form.get("address", "").strip()
        city = form.get("city", "").strip()
        state = form.get("state", "").strip()
        pin_code = form.get("pin_code", "").strip()
        guardian_name = form.get("guardian_name", "").strip()
        guardian_phone = form.get("guardian_phone", "").strip()

        if not all([name, email, password, confirm_password, phone,
                    roll_number, department, course, residence_type]):
            flash("Please fill in all required fields.")
            return redirect(url_for("register"))

        if not valid_email(email):
            flash("Enter a valid email address.")
            return redirect(url_for("register"))

        if len(password) < MIN_PASSWORD or len(password) > MAX_PASSWORD:
            flash(f"Password must be between {MIN_PASSWORD} and {MAX_PASSWORD} characters.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        lengths = {
            "name": name, "roll_number": roll_number, "course": course,
            "specialization": specialization, "college": college, "section": section,
            "address": address, "city": city, "state": state, "guardian_name": guardian_name,
        }
        for key, value in lengths.items():
            if len(value) > MAX_LENGTHS[key]:
                flash("One of the fields is too long. Please shorten it.")
                return redirect(url_for("register"))

        if not phone.isdigit() or len(phone) != 10:
            flash("Enter a valid 10-digit contact number.")
            return redirect(url_for("register"))

        if alternate_phone and (not alternate_phone.isdigit() or len(alternate_phone) != 10):
            flash("Enter a valid 10-digit alternate number.")
            return redirect(url_for("register"))

        if guardian_phone and (not guardian_phone.isdigit() or len(guardian_phone) != 10):
            flash("Enter a valid 10-digit guardian number.")
            return redirect(url_for("register"))

        if pin_code and (not pin_code.isdigit() or len(pin_code) != 6):
            flash("Enter a valid 6-digit PIN code.")
            return redirect(url_for("register"))

        if course not in DEPARTMENT_COURSES.get(department, []):
            flash("Please select a valid course for your department.")
            return redirect(url_for("register"))

        if residence_type not in ("Hosteller", "Day Scholar"):
            flash("Please select a valid residence type.")
            return redirect(url_for("register"))

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
        if admission_year is not None and not 1990 <= admission_year <= datetime.now().year + 1:
            flash("Enter a valid admission year.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'student')",
                (name, email, hashed_password),
            )
            user_id = cursor.lastrowid

            conn.execute(
                """
                INSERT INTO students (
                    user_id, roll_number, course, dob, gender, phone, alternate_phone,
                    department, specialization, year, semester, admission_year, section,
                    college, address, city, state, pin_code, guardian_name, guardian_phone,
                    residence_type
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, roll_number, course, dob or None, gender or None, phone,
                    alternate_phone or None, department, specialization or None, year,
                    semester, admission_year, section or None, college or None,
                    address or None, city or None, state or None, pin_code or None,
                    guardian_name or None, guardian_phone or None, residence_type,
                ),
            )
            conn.commit()
            flash("Registration successful! You can now log in.")

        except IntegrityError:
            conn.rollback()
            flash("Email or roll number already exists.")

        except Exception:
            conn.rollback()
            log.exception("Registration failed")
            flash("Registration failed. Please try again.")

        finally:
            conn.close()

        return redirect(url_for("register"))

    return render_template("register.html")


# =========================================================
# STUDENT LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if not limiter.allow(f"login:{client_ip()}", config.LOGIN_IP_LIMIT, 600):
            flash("Too many login attempts from this network. Please wait a few minutes.")
            return redirect(url_for("login"))

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")[:MAX_PASSWORD]
        next_url = request.form.get("next", "")

        user, error = attempt_login(email, password)

        if error:
            flash(error)
            return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

        if user["role"] != "student":
            flash("This account is registered as a teacher. Please use Faculty Login.")
            return redirect(url_for("login"))

        login_user(user)
        log.info("Student login user_id=%s", user["id"])

        if is_safe_next_url(next_url):
            return redirect(next_url)

        return redirect(url_for("student_dashboard"))

    return render_template("login.html")


# =========================================================
# FACULTY LOGIN
# =========================================================

@app.route("/faculty_login", methods=["GET", "POST"])
def faculty_login():

    if request.method == "POST":

        if not limiter.allow(f"login:{client_ip()}", config.LOGIN_IP_LIMIT, 600):
            flash("Too many login attempts from this network. Please wait a few minutes.")
            return redirect(url_for("faculty_login"))

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")[:MAX_PASSWORD]

        user, error = attempt_login(email, password)

        if error:
            flash(error)
            return redirect(url_for("faculty_login"))

        if user["role"] != "teacher":
            flash("This account is registered as a student. Please use Student Login.")
            return redirect(url_for("faculty_login"))

        login_user(user)
        log.info("Teacher login user_id=%s", user["id"])
        return redirect(url_for("teacher_dashboard"))

    return render_template("faculty_login.html")


# =========================================================
# TEACHER SIGN-UP (needs the college sign-up code from config)
# =========================================================

@app.route("/faculty_register", methods=["GET", "POST"])
def faculty_register():

    enabled = bool(config.TEACHER_SIGNUP_CODE)

    if request.method == "POST":

        if not enabled:
            flash("Teacher sign-up is turned off. Ask your administrator.")
            return redirect(url_for("faculty_register"))

        if not limiter.allow(f"tregister:{client_ip()}", 10, 3600):
            flash("Too many sign-up attempts. Please try again later.")
            return redirect(url_for("faculty_register"))

        name, name_ok = _clean_text(request.form.get("name"), 100)
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        code = request.form.get("teacher_code", "").strip()

        if not name or not valid_email(email):
            flash("Enter your name and a valid email address.")
        elif not name_ok:
            flash("Name is too long.")
        elif len(password) < MIN_PASSWORD or len(password) > MAX_PASSWORD:
            flash(f"Password must be between {MIN_PASSWORD} and {MAX_PASSWORD} characters.")
        elif password != confirm:
            flash("Passwords do not match.")
        elif not hmac.compare_digest(code.encode("utf-8"), config.TEACHER_SIGNUP_CODE.encode("utf-8")):
            flash("The sign-up code is incorrect.")
        else:
            conn = get_db_connection()
            try:
                conn.execute(
                    "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'teacher')",
                    (name, email, generate_password_hash(password)),
                )
                conn.commit()
                log.info("Teacher account created via sign-up")
                flash("Teacher account created. You can log in now.")
                return redirect(url_for("faculty_login"))
            except IntegrityError:
                conn.rollback()
                flash("An account with this email already exists.")
            except Exception:
                conn.rollback()
                log.exception("Teacher sign-up failed")
                flash("Sign-up failed. Please try again.")
            finally:
                conn.close()

        return redirect(url_for("faculty_register"))

    return render_template("faculty_register.html", enabled=enabled)


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
# CHANGE PASSWORD (signed-in users)
# Changing the password signs out every other device, because each session is
# tied to the password it was started with.
# =========================================================

@app.route("/account/password", methods=["GET", "POST"])
def change_password():

    if "user_id" not in session or session.get("role") not in ("student", "teacher"):
        return redirect(url_for("login"))

    role = session["role"]
    back = url_for("teacher_dashboard") if role == "teacher" else url_for("student_dashboard")

    if request.method == "POST":

        if not limiter.allow(f"chgpw:{session['user_id']}", 10, 900):
            flash("Too many attempts. Please wait a few minutes.")
            return redirect(url_for("change_password"))

        current = request.form.get("current_password", "")[:MAX_PASSWORD]
        new = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT password FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()

            if row is None:
                flash("Account not found.")
                return redirect(url_for("login"))

            if not check_password_hash(row["password"], current):
                flash("Your current password is incorrect.")
            elif len(new) < MIN_PASSWORD or len(new) > MAX_PASSWORD:
                flash(f"New password must be between {MIN_PASSWORD} and {MAX_PASSWORD} characters.")
            elif new != confirm:
                flash("The new passwords do not match.")
            elif check_password_hash(row["password"], new):
                flash("Choose a password different from your current one.")
            else:
                new_hash = generate_password_hash(new)
                conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, session["user_id"]))
                conn.commit()
                refresh_password_fingerprint(new_hash)
                log.info("Password changed user_id=%s", session["user_id"])
                flash("Your password has been changed. You stay signed in on this device.")
                return redirect(back)
        finally:
            conn.close()

    return render_template("password_reset.html", mode="change", role=role, back=back)


# =========================================================
# STUDENT DASHBOARD
# =========================================================

@app.route("/student/dashboard")
def student_dashboard():

    if not is_student_logged_in():
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        student = conn.execute(
            """
            SELECT users.name, users.email, students.id AS student_id,
                   students.roll_number, students.course, students.department,
                   students.specialization, students.year, students.semester,
                   students.section, students.residence_type
            FROM users
            JOIN students ON users.id = students.user_id
            WHERE users.id = ?
            """,
            (session["user_id"],),
        ).fetchone()

        if student is None:
            session.clear()
            flash("Student profile not found.")
            return redirect(url_for("login"))

        # Only finished sessions (closed or expired) are counted, so a
        # session that is still running does not lower the percentage.
        now_iso = _now_iso()

        attendance_stats = conn.execute(
            f"""
            SELECT COUNT(*) AS total_classes,
                   SUM(CASE WHEN r.status = 'Present' THEN 1 ELSE 0 END) AS classes_attended
            FROM attendance_records r
            JOIN attendance_sessions s ON s.id = r.session_id
            WHERE r.student_id = :student_id AND {FINISHED_SESSION}
            """,
            {"student_id": student["student_id"], "now": now_iso},
        ).fetchone()

        subject_rows = conn.execute(
            f"""
            SELECT sub.subject_name, sub.subject_code,
                   COUNT(*) AS total,
                   SUM(CASE WHEN r.status = 'Present' THEN 1 ELSE 0 END) AS attended
            FROM attendance_records r
            JOIN attendance_sessions s ON s.id = r.session_id
            JOIN subjects sub ON sub.id = s.subject_id
            WHERE r.student_id = :student_id AND {FINISHED_SESSION}
            GROUP BY sub.id
            ORDER BY sub.subject_name
            """,
            {"student_id": student["student_id"], "now": now_iso},
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
            JOIN subjects sub ON sub.id = s.subject_id
            WHERE r.student_id = ?
            ORDER BY s.id DESC
            """,
            (student["student_id"],),
        ).fetchall()

        total_classes = attendance_stats["total_classes"] or 0
        classes_attended = attendance_stats["classes_attended"] or 0
        attendance_percentage = (
            round((classes_attended / total_classes) * 100, 1) if total_classes > 0 else 0
        )

        return render_template(
            "student_dashboard.html",
            student=student,
            total_classes=total_classes,
            classes_attended=classes_attended,
            attendance_percentage=attendance_percentage,
            attendance_history=attendance_history,
            subject_cards=subject_cards,
            min_attendance=MIN_ATTENDANCE,
        )

    finally:
        conn.close()


# =========================================================
# TEACHER DASHBOARD
# =========================================================

@app.route("/teacher/dashboard")
def teacher_dashboard():

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    conn = get_db_connection()

    try:
        teacher = conn.execute(
            "SELECT name, email FROM users WHERE id = ? AND role = 'teacher'",
            (session["user_id"],),
        ).fetchone()

        if teacher is None:
            session.clear()
            flash("Teacher account not found.")
            return redirect(url_for("faculty_login"))

        # Privacy: a teacher sees only the students in THEIR OWN classes (no emails
        # of students outside those classes) and only attendance from THEIR OWN sessions.
        total_students = conn.execute(
            """
            SELECT COUNT(DISTINCT se.student_id)
            FROM student_enrollments se
            JOIN classes c ON c.id = se.class_id
            WHERE c.created_by = ?
            """,
            (session["user_id"],),
        ).fetchone()[0]

        total_attendance = conn.execute(
            """
            SELECT COUNT(*)
            FROM attendance_records ar
            JOIN attendance_sessions s ON s.id = ar.session_id
            WHERE s.teacher_id = ? AND ar.status = 'Present'
            """,
            (session["user_id"],),
        ).fetchone()[0]

        students = conn.execute(
            """
            SELECT DISTINCT users.name, users.email, students.roll_number, students.department,
                   students.course, students.year, students.semester, students.residence_type
            FROM student_enrollments se
            JOIN classes c ON c.id = se.class_id
            JOIN students ON students.id = se.student_id
            JOIN users ON users.id = students.user_id
            WHERE c.created_by = ? AND users.role = 'student'
            ORDER BY students.roll_number
            """,
            (session["user_id"],),
        ).fetchall()

        return render_template(
            "teacher_dashboard.html",
            teacher=teacher,
            total_students=total_students,
            total_attendance=total_attendance,
            students=students,
        )

    finally:
        conn.close()


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
                class_name, ok1 = _clean_text(request.form.get("class_name"), 100)
                section, ok2 = _clean_text(request.form.get("section"), 10)
                section = section.upper()

                if not class_name or not section:
                    flash("Class name and section are required.")
                elif not (ok1 and ok2):
                    flash("Class name or section is too long.")
                else:
                    try:
                        conn.execute(
                            "INSERT INTO classes (class_name, section, created_by) VALUES (?, ?, ?)",
                            (class_name, section, teacher_id),
                        )
                        conn.commit()
                        flash("Class created successfully.")
                    except IntegrityError:
                        conn.rollback()
                        flash("You already have this class and section.")

            elif form_type == "subject":
                subject_name, ok1 = _clean_text(request.form.get("subject_name"), 100)
                subject_code, ok2 = _clean_text(request.form.get("subject_code"), 20)
                subject_code = subject_code.upper()

                if not subject_name or not subject_code:
                    flash("Subject name and code are required.")
                elif not (ok1 and ok2):
                    flash("Subject name or code is too long.")
                else:
                    try:
                        conn.execute(
                            "INSERT INTO subjects (subject_name, subject_code, created_by) VALUES (?, ?, ?)",
                            (subject_name, subject_code, teacher_id),
                        )
                        conn.commit()
                        flash("Subject created successfully.")
                    except IntegrityError:
                        conn.rollback()
                        flash("You already have a subject with this code.")

            return redirect(url_for("teacher_classes"))

        classes = conn.execute(
            """
            SELECT c.id, c.class_name, c.section,
                   (SELECT COUNT(*) FROM student_enrollments e WHERE e.class_id = c.id) AS student_count,
                   (SELECT COUNT(*) FROM attendance_sessions s WHERE s.class_id = c.id) AS session_count
            FROM classes c
            WHERE c.created_by = ?
            ORDER BY c.class_name, c.section
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

    finally:
        conn.close()

    return render_template("teacher_classes.html", classes=classes, subjects=subjects)


@app.route("/teacher/classes/<int:class_id>/delete", methods=["POST"])
def delete_class(class_id):
    """Delete one of the teacher's classes. Enrollments, sessions and attendance go with it.
    Student accounts are kept.
    """
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    conn = get_db_connection()
    try:
        target = conn.execute(
            "SELECT id, class_name, section FROM classes WHERE id = ? AND created_by = ?",
            (class_id, session["user_id"]),
        ).fetchone()

        if target is None:
            flash("Class not found.")
        else:
            conn.execute("DELETE FROM classes WHERE id = ?", (class_id,))
            conn.commit()
            flash(f"Class {target['class_name']} - {target['section']} was deleted.")
    finally:
        conn.close()

    return redirect(url_for("teacher_classes"))


# =========================================================
# TEACHER: ENROLL STUDENTS IN CLASSES
# =========================================================

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
                    "INSERT INTO student_enrollments (class_id, student_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
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
                    SELECT student_id FROM student_enrollments WHERE class_id = ?
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


@app.route("/teacher/enrollments/remove", methods=["POST"])
def remove_enrollment():
    """Take a student out of one of the teacher's classes.

    Their attendance for that class's sessions is deleted too, so a mistaken
    enrollment leaves no trace in the reports.
    """
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    class_id = request.form.get("class_id", type=int)
    student_id = request.form.get("student_id", type=int)

    conn = get_db_connection()
    try:
        owned = None
        if class_id:
            owned = conn.execute(
                "SELECT id FROM classes WHERE id = ? AND created_by = ?",
                (class_id, session["user_id"]),
            ).fetchone()
        if owned is None or not student_id:
            flash("Please choose one of your own classes.")
            return redirect(url_for("teacher_enrollments"))

        student = conn.execute(
            "SELECT u.name FROM students s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
            (student_id,),
        ).fetchone()

        cursor = conn.execute(
            "DELETE FROM student_enrollments WHERE class_id = ? AND student_id = ?",
            (class_id, student_id),
        )
        if cursor.rowcount == 0:
            conn.rollback()
            flash("That student is not in this class.")
        else:
            conn.execute(
                """
                DELETE FROM attendance_records
                WHERE student_id = ?
                  AND session_id IN (SELECT id FROM attendance_sessions WHERE class_id = ?)
                """,
                (student_id, class_id),
            )
            conn.commit()
            log.info("Student removed from class class_id=%s student_id=%s", class_id, student_id)
            flash(f"{student['name'] if student else 'Student'} was removed from the class.")
    finally:
        conn.close()

    return redirect(url_for("teacher_enrollments", class_id=class_id))


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

            # Duplicate-session guard. BEGIN IMMEDIATE holds the write lock, so two
            # simultaneous "start" clicks cannot both pass the check.
            conn.begin_write()
            running = conn.execute(
                """
                SELECT start_time, expires_at
                FROM attendance_sessions
                WHERE class_id = ? AND status = 'open' AND expires_at > ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (class_id, _now_iso()),
            ).fetchone()
            if running:
                conn.rollback()
                flash(
                    f"A session for this class is already running "
                    f"(started {running['start_time'][11:16]}, ends {running['expires_at'][11:16]}). "
                    f"Close it first, then start a new one."
                )
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
                    class_id, subject_id, teacher_id, now.date().isoformat(),
                    now.isoformat(timespec="seconds"), expires.isoformat(timespec="seconds"),
                    secrets.token_urlsafe(32),  # secret; never sent to the browser
                ),
            )
            session_id = cursor.lastrowid

            # Every enrolled student starts as Absent. A scan changes that to Present.
            cursor = conn.execute(
                """
                INSERT INTO attendance_records (session_id, student_id, status)
                SELECT CAST(? AS INTEGER), student_id, 'Absent'
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
        now_iso=_now_iso(),  # lets the page tell a LIVE session from one that has expired
    )


# =========================================================
# TEACHER: SESSION QR CODE (live, rotating)
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


def _is_open(s, now_iso):
    return s["status"] == "open" and s["expires_at"] > now_iso


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
                   ar.marked_at
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
    now_iso = _now_iso()
    is_open = _is_open(s, now_iso)
    window = _qr_window()

    return render_template(
        "teacher_session_qr.html",
        s=s,
        is_open=is_open,
        scan_url=build_scan_url(s["id"], current_qr_code(s["qr_token"])) if is_open else "",
        # The image URL changes with each window, so the page knows when to swap it.
        qr_src=url_for("session_qr_image", session_id=s["id"]) + f"?w={window}",
        now_iso=now_iso,
        attendance_rows=attendance_rows,
        present_count=present_count,
        total_students=len(attendance_rows),
    )


@app.route("/teacher/sessions/<int:session_id>/qr.json")
def session_qr_state(session_id):
    """Current QR code for the live page. Polled every second so codes never look stale."""
    if not is_teacher_logged_in():
        abort(401)

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    if not _is_open(s, _now_iso()):
        return {"open": False}

    window = _qr_window()
    return {
        "open": True,
        "src": url_for("session_qr_image", session_id=s["id"]) + f"?w={window}",
        "link": build_scan_url(s["id"], current_qr_code(s["qr_token"])),
        "seconds_left": config.QR_ROTATE_SECONDS - (time.time() % config.QR_ROTATE_SECONDS),
    }


@app.route("/teacher/sessions/<int:session_id>/qr.png")
def session_qr_image(session_id):

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s or not _is_open(s, _now_iso()):
        abort(404)

    img = qrcode.make(build_scan_url(s["id"], current_qr_code(s["qr_token"])))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    response = send_file(buf, mimetype="image/png")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/teacher/sessions/<int:session_id>/close", methods=["POST"])
def close_session(session_id):

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE attendance_sessions SET status = 'closed' WHERE id = ? AND teacher_id = ?",
            (session_id, session["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    if cursor.rowcount == 0:
        abort(404)

    flash("Session closed. Students who did not scan stay marked Absent.")
    return redirect(url_for("teacher_sessions"))


@app.route("/teacher/sessions/<int:session_id>/attendance", methods=["POST"])
def set_manual_attendance(session_id):
    """Teacher marks one enrolled student Present or Absent by hand."""
    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    student_id = request.form.get("student_id", type=int)
    status = request.form.get("status", "")
    if not student_id or status not in ("Present", "Absent"):
        abort(400)

    now_iso = _now_iso()
    conn = get_db_connection()
    try:
        enrolled = conn.execute(
            "SELECT 1 FROM student_enrollments WHERE class_id = ? AND student_id = ?",
            (s["class_id"], student_id),
        ).fetchone()
        if not enrolled:
            abort(404)

        conn.execute(
            """
            INSERT INTO attendance_records (session_id, student_id, status, marked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (session_id, student_id)
            DO UPDATE SET status = excluded.status, marked_at = excluded.marked_at
            """,
            (session_id, student_id, status, now_iso if status == "Present" else None),
        )
        conn.commit()
    finally:
        conn.close()

    log.info("Manual attendance session=%s student_id=%s status=%s", session_id, student_id, status)
    flash(f"Marked {status.lower()} by hand.")
    return redirect(url_for("session_qr_page", session_id=session_id))


# =========================================================
# TEACHER: ATTENDANCE REPORTS
# =========================================================

def _class_report_rows(conn, class_id, teacher_id, now_iso):
    """Per-student totals for one class. Only finished sessions are counted."""
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
              AND {FINISHED_SESSION}
        ) x ON x.student_id = st.id
        WHERE se.class_id = :class_id
        GROUP BY st.id, u.id
        ORDER BY st.roll_number
        """,
        {"class_id": class_id, "teacher_id": teacher_id, "now": now_iso},
    ).fetchall()

    result = []
    for r in rows:
        pct = attendance_percent(r["attended"], r["total"])
        result.append({
            "id": r["id"],
            "roll_number": r["roll_number"],
            "name": r["name"],
            "total": r["total"],
            "attended": r["attended"],
            "absent": r["total"] - r["attended"],
            "percent": pct,
            "level": attendance_level(pct, r["total"]),
        })
    return result


@app.route("/teacher/reports")
def teacher_reports():

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    teacher_id = session["user_id"]
    now_iso = _now_iso()
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

        class_id = request.args.get("class_id", type=int)
        student_id = request.args.get("student_id", type=int)

        if class_id:
            selected = conn.execute(
                "SELECT id, class_name, section FROM classes WHERE id = ? AND created_by = ?",
                (class_id, teacher_id),
            ).fetchone()

        if selected:
            class_sessions = conn.execute(
                f"""
                SELECT COUNT(*) FROM attendance_sessions s
                WHERE s.class_id = :class_id AND s.teacher_id = :teacher_id
                  AND {FINISHED_SESSION}
                """,
                {"class_id": selected["id"], "teacher_id": teacher_id, "now": now_iso},
            ).fetchone()[0]

            student_rows = _class_report_rows(conn, selected["id"], teacher_id, now_iso)

            if student_id:
                chosen_student = next((r for r in student_rows if r["id"] == student_id), None)

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
                      AND {FINISHED_SESSION}
                    GROUP BY sub.id
                    ORDER BY sub.subject_name
                    """,
                    {
                        "student_id": chosen_student["id"],
                        "class_id": selected["id"],
                        "teacher_id": teacher_id,
                        "now": now_iso,
                    },
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
                        "level": attendance_level(pct, c["total"]),
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
        min_attendance=MIN_ATTENDANCE,
    )


def _csv_cell(value):
    """Stop spreadsheet formula injection: a cell starting with = + - @ is treated as a formula."""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def _safe_filename(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "report"


@app.route("/teacher/reports/export.csv")
def export_report_csv():
    """Download one class's attendance as a CSV file (opens in Excel)."""

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    class_id = request.args.get("class_id", type=int)
    conn = get_db_connection()
    try:
        owned = conn.execute(
            "SELECT id, class_name, section FROM classes WHERE id = ? AND created_by = ?",
            (class_id, session["user_id"]),
        ).fetchone() if class_id else None

        if owned is None:
            abort(404)

        rows = _class_report_rows(conn, owned["id"], session["user_id"], _now_iso())
    finally:
        conn.close()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Roll Number", "Name", "Sessions Held", "Present", "Absent",
                     "Attendance %", f"Below {MIN_ATTENDANCE}%"])
    for r in rows:
        below = "Yes" if r["total"] and r["percent"] < MIN_ATTENDANCE else "No"
        writer.writerow([
            _csv_cell(r["roll_number"]), _csv_cell(r["name"]),
            r["total"], r["attended"], r["absent"], f"{r['percent']}", below,
        ])

    # The BOM makes Excel read the file as UTF-8, so names display correctly.
    content = "\ufeff" + buf.getvalue()
    filename = _safe_filename(f"attendance-{owned['class_name']}-{owned['section']}") + ".csv"
    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# =========================================================
# STUDENT: SCAN QR AND MARK ATTENDANCE
# URL: /attend/<session id>/<code>  (the code changes every QR_ROTATE_SECONDS)
# =========================================================

@app.route("/attend/<int:session_id>/<code>")
def mark_attendance(session_id, code):

    if not is_student_logged_in():
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
            "SELECT id, class_id, qr_token, status, expires_at FROM attendance_sessions WHERE id = ?",
            (session_id,),
        ).fetchone()

        if not attendance_session:
            return render_template("attend_result.html", ok=False, message="This QR code is not valid.")

        now_iso = _now_iso()

        if attendance_session["status"] != "open" or attendance_session["expires_at"] <= now_iso:
            return render_template("attend_result.html", ok=False,
                                   message="This attendance session has closed.")

        if not qr_code_is_valid(attendance_session["qr_token"], code):
            return render_template(
                "attend_result.html", ok=False,
                message="This QR code has changed. Please scan the code now on the screen.",
            )

        enrolled = conn.execute(
            "SELECT 1 FROM student_enrollments WHERE class_id = ? AND student_id = ?",
            (attendance_session["class_id"], student["id"]),
        ).fetchone()

        if not enrolled:
            return render_template("attend_result.html", ok=False,
                                   message="You are not enrolled in this class.")

        record = conn.execute(
            "SELECT id, status FROM attendance_records WHERE session_id = ? AND student_id = ?",
            (attendance_session["id"], student["id"]),
        ).fetchone()

        if record and record["status"] == "Present":
            return render_template("attend_result.html", ok=True,
                                   message="Your attendance is already marked for this session.")

        try:
            if record:
                conn.execute(
                    "UPDATE attendance_records SET status = 'Present', marked_at = ? WHERE id = ?",
                    (now_iso, record["id"]),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO attendance_records (session_id, student_id, status, marked_at)
                    VALUES (?, ?, 'Present', ?)
                    """,
                    (attendance_session["id"], student["id"], now_iso),
                )
            conn.commit()
        except IntegrityError:
            # Two scans arrived at the same moment. The first one already counted.
            conn.rollback()
            return render_template("attend_result.html", ok=True,
                                   message="Your attendance is already marked for this session.")

        log.info("Attendance marked session=%s student_id=%s", session_id, student["id"])

        return render_template("attend_result.html", ok=True,
                               message="Attendance marked as Present.")

    finally:
        conn.close()


@app.route("/attend/<path:rest>")
def attend_invalid(rest):
    """Any other /attend/ link, such as an old QR code printed before the update."""
    return render_template("attend_result.html", ok=False,
                           message="This QR code is not valid. Please scan the latest code.")


# ============================================================
# PASSWORD RESET (students and teachers)
# ============================================================

def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _reset_link(token):
    # Use the configured public address, never the Host header. A forged Host header
    # could otherwise send a victim a reset link that points at an attacker's site.
    base = config.PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return f"{base}{url_for('reset_password', token=token)}"


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
        + str(config.RESET_TOKEN_MINUTES) + " minutes:\n\n" + link
        + "\n\nIf you did not ask for this, you can ignore this email."
    )
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as server:
        server.starttls()
        if config.SMTP_USER:
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
        server.send_message(msg)


def _deliver_reset_email(to_email, link):
    """Send in the background so the response time does not reveal whether the account exists."""
    try:
        send_reset_email(to_email, link)
    except Exception:
        log.exception("Password reset email could not be sent")


def _issue_reset(email):
    """Create a reset token for a known account, if the cooldown allows it."""
    now = datetime.now()
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:
            return

        last = conn.execute(
            "SELECT expires_at FROM password_resets WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
        if last is not None:
            requested_at = datetime.fromisoformat(last["expires_at"]) - timedelta(minutes=config.RESET_TOKEN_MINUTES)
            if (now - requested_at).total_seconds() < config.RESET_REQUEST_COOLDOWN_SECONDS:
                return  # a link was just sent; do not flood the inbox

        token = secrets.token_urlsafe(32)
        expires = (now + timedelta(minutes=config.RESET_TOKEN_MINUTES)).isoformat(timespec="seconds")
        conn.execute("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0", (user["id"],))
        conn.execute(
            "INSERT INTO password_resets (user_id, token_hash, expires_at, used) VALUES (?, ?, ?, 0)",
            (user["id"], _hash_token(token), expires),
        )
        conn.commit()
    finally:
        conn.close()

    threading.Thread(
        target=_deliver_reset_email,
        args=(user["email"], _reset_link(token)),
        daemon=True,
    ).start()


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    role = request.values.get("role", "student")
    if role not in ("student", "teacher"):
        role = "student"
    back = url_for("faculty_login") if role == "teacher" else url_for("login")
    sent = False

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if valid_email(email) and limiter.allow(f"forgot:{client_ip()}", 20, 3600):
            _issue_reset(email)
        # Same answer whether or not the email exists, so people cannot guess accounts.
        sent = True

    return render_template("password_reset.html", mode="request", role=role, back=back, sent=sent)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if len(token) > 200:
        abort(404)

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

        now_iso = _now_iso()
        if row is None or row["used"] != 0 or row["expires_at"] <= now_iso:
            return render_template("password_reset.html", mode="invalid", role="student",
                                   back=url_for("login"))

        back = url_for("faculty_login") if row["role"] == "teacher" else url_for("login")

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if len(password) < MIN_PASSWORD or len(password) > MAX_PASSWORD:
                flash(f"Password must be between {MIN_PASSWORD} and {MAX_PASSWORD} characters.")
            elif password != confirm:
                flash("Passwords do not match.")
            else:
                conn.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(password), row["user_id"]),
                )
                conn.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (row["user_id"],))
                conn.commit()
                log.info("Password reset completed user_id=%s", row["user_id"])
                flash("Your password has been reset. Please log in with your new password.")
                return redirect(back)

        return render_template("password_reset.html", mode="reset", role=row["role"],
                               back=back, token=token)
    finally:
        conn.close()


if __name__ == "__main__":
    ssl_ctx = "adhoc" if config.USE_HTTPS else None
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, ssl_context=ssl_ctx)