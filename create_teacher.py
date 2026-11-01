#Teacher
from database import get_db_connection
from werkzeug.security import generate_password_hash
from getpass import getpass


def create_teacher():
    print("=== SmartAttend Teacher Setup ===")

    name = input("Enter teacher name: ").strip()
    email = input("Enter teacher email: ").strip().lower()
    password = getpass("Enter teacher password: ")

    if not name or not email or not password:
        print("All fields are required.")
        return

    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()

    try:
        existing_user = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            print("An account with this email already exists.")
            return

        conn.execute(
            """
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, 'teacher')
            """,
            (name, email, hashed_password)
        )

        conn.commit()
        print("Teacher account created successfully!")

    except Exception:
        conn.rollback()
        print("Could not create teacher account.")

    finally:
        conn.close()


if __name__ == "__main__":
    create_teacher()