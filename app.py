import secrets

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash
)

from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


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
            return redirect(url_for("login"))

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

@app.route("/logout")
def logout():

    previous_role = session.get("role")

    session.clear()
    flash("You have been logged out.")

    if previous_role == "teacher":
        return redirect(url_for("faculty_login"))

    return redirect(url_for("login"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)