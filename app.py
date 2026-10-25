# Main application file for the QR Attendance System
import io
import secrets
import sqlite3
from datetime import datetime, timedelta

import qrcode
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash

import config
from database import get_db_connection


app = Flask(__name__)
app.secret_key = config.SECRET_KEY


# =========================================================
# HELPERS
# =========================================================

def is_teacher_logged_in():
    return "user_id" in session and session.get("role") == "teacher"


def is_safe_next_url(url):
    """Allow only local paths like /attend/abc. Block other sites."""
    return (
        bool(url)
        and url.startswith("/")
        and not url.startswith("//")
        and "\\" not in url
    )


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

        # Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
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

        conn = get_db_connection()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        finally:
            conn.close()

        if not user or not check_password_hash(
            user["password"], password
        ):
            flash("Invalid email or password.")
            return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

        if user["role"] != "student":
            flash(
                "This account is registered as a teacher. "
                "Please use Faculty Login."
            )
            return redirect(url_for("login"))

        session.clear()
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

        conn = get_db_connection()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        finally:
            conn.close()

        if not user or not check_password_hash(
            user["password"], password
        ):
            flash("Invalid email or password.")
            return redirect(url_for("faculty_login"))

        if user["role"] != "teacher":
            flash(
                "This account is registered as a student. "
                "Please use Student Login."
            )
            return redirect(url_for("faculty_login"))

        session.clear()
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

        attendance_stats = conn.execute(
            """
            SELECT
                COUNT(*) AS total_classes,
                SUM(
                    CASE
                        WHEN status = 'Present' THEN 1
                        ELSE 0
                    END
                ) AS classes_attended
            FROM attendance
            WHERE student_id = ?
            """,
            (student["student_id"],)
        ).fetchone()

        attendance_history = conn.execute(
            """
            SELECT attendance_date, status
            FROM attendance
            WHERE student_id = ?
            ORDER BY attendance_date DESC
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
            attendance_history=attendance_history
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

        total_students = conn.execute(
            """
            SELECT COUNT(*)
            FROM students
            JOIN users ON students.user_id = users.id
            WHERE users.role = 'student'
            """
        ).fetchone()[0]

        total_attendance = conn.execute(
            """
            SELECT COUNT(*)
            FROM attendance
            WHERE status = 'Present'
            """
        ).fetchone()[0]

        students = conn.execute(
            """
            SELECT
                users.name,
                users.email,
                students.roll_number,
                students.department,
                students.course,
                students.year,
                students.semester,
                students.residence_type
            FROM students
            JOIN users ON students.user_id = users.id
            WHERE users.role = 'student'
            ORDER BY students.roll_number
            """
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
                SELECT s.roll_number, s.course, u.name
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
            SELECT s.id, s.qr_token, s.expires_at, s.status, s.session_date,
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


def build_scan_url(token):
    base = config.PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return f"{base}/attend/{token}"


@app.route("/teacher/sessions/<int:session_id>")
def session_qr_page(session_id):

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    now_iso = datetime.now().isoformat(timespec="seconds")
    is_open = s["status"] == "open" and s["expires_at"] > now_iso

    return render_template(
        "teacher_session_qr.html",
        s=s,
        is_open=is_open,
        scan_url=build_scan_url(s["qr_token"]),
    )


@app.route("/teacher/sessions/<int:session_id>/qr.png")
def session_qr_image(session_id):

    if not is_teacher_logged_in():
        return redirect(url_for("faculty_login"))

    s = get_owned_session(session_id)
    if not s:
        abort(404)

    img = qrcode.make(build_scan_url(s["qr_token"]))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


# =========================================================
# STUDENT: SCAN QR AND MARK ATTENDANCE
# =========================================================

@app.route("/attend/<token>")
def mark_attendance(token):

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
            SELECT id, class_id, status, expires_at
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

        return render_template(
            "attend_result.html", ok=True,
            message="Attendance marked as Present."
        )

    finally:
        conn.close()


if __name__ == "__main__":
    ssl_ctx = "adhoc" if config.USE_HTTPS else None
    app.run(host=config.HOST, debug=config.DEBUG, ssl_context=ssl_ctx)