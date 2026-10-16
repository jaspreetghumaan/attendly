import secrets
from flask import Flask, render_template,  request, redirect, session, url_for, flash
from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash 
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


@app.route("/")
def home():
    return render_template("index.html")

#Register routes
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        roll_number = request.form["roll_number"].strip()
        course = request.form["course"].strip()

        if not all([name, email, password, roll_number, course]):
            flash("All fields are required.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return redirect(url_for("register"))

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
                INSERT INTO students (user_id, roll_number, course)
                VALUES (?, ?, ?)
                """,
                (user_id, roll_number, course)
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
#Login routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        print("Entered email:", email)
        print("Password received:", bool(password))

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("student_dashboard"))

        flash("Invalid email or password.")
        return redirect(url_for("login"))

    return render_template("login.html")

#Student dashboard route
@app.route("/student/dashboard")
def student_dashboard():
    if "user_id" not in session or session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()

    student = conn.execute(
        """
        SELECT users.name, users.email, students.roll_number, students.course
        FROM users
        JOIN students ON users.id = students.user_id
        WHERE users.id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    conn.close()

    return render_template("student_dashboard.html", student=student)

#Logout route
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

#Admin dashboard route
@app.route("/admin/dashboard")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db_connection()

    total_students = conn.execute(
        "SELECT COUNT(*) FROM students"
    ).fetchone()[0]

    total_attendance = conn.execute(
        "SELECT COUNT(*) FROM attendance WHERE status = 'Present'"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "admin_dashboard.html",
        total_students=total_students,
        total_attendance=total_attendance
    )

if __name__ == "__main__":
    app.run(debug=True)