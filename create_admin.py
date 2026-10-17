from database import get_db_connection
from werkzeug.security import generate_password_hash
from getpass import getpass


def create_admin():
    print("=== SmartAttend Admin Setup ===")

    name = input("Enter admin name: ").strip()
    email = input("Enter admin email: ").strip().lower()
    password = getpass("Enter admin password: ")

    if not name or not email or not password:
        print("All fields are required.")
        return

    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()

    try:
        conn.execute(
            """
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, 'admin')
            """,
            (name, email, hashed_password)
        )

        conn.commit()
        print("Admin account created successfully!")

    except Exception as error:
        conn.rollback()

        if "UNIQUE constraint failed" in str(error):
            print("An account with this email already exists.")
        else:
            print("Could not create admin account.")

    finally:
        conn.close()


if __name__ == "__main__":
    create_admin()