#backup
import sqlite3


def get_db_connection():
    conn = sqlite3.connect("smartattend.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables():
    conn = get_db_connection()

    try:
        # Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('admin', 'student'))
            )
        """)

        # Students table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                roll_number TEXT UNIQUE NOT NULL,
                course TEXT NOT NULL,

                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        # Add new registration columns to existing databases.
        # Existing student data will remain unchanged.
        existing_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(students)"
            ).fetchall()
        }

        new_columns = {
            "dob": "TEXT",
            "gender": "TEXT",
            "phone": "TEXT",
            "alternate_phone": "TEXT",
            "department": "TEXT",
            "specialization": "TEXT",
            "year": "INTEGER",
            "semester": "INTEGER",
            "admission_year": "INTEGER",
            "section": "TEXT",
            "college": "TEXT",
            "address": "TEXT",
            "city": "TEXT",
            "state": "TEXT",
            "pin_code": "TEXT",
            "guardian_name": "TEXT",
            "guardian_phone": "TEXT",
            "residence_type": "TEXT"
        }

        for column_name, column_type in new_columns.items():
            if column_name not in existing_columns:
                conn.execute(
                    f"ALTER TABLE students ADD COLUMN "
                    f"{column_name} {column_type}"
                )

        # Attendance table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                attendance_date TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (status IN ('Present', 'Absent')),

                FOREIGN KEY (student_id)
                    REFERENCES students(id)
                    ON DELETE CASCADE,

                UNIQUE (student_id, attendance_date)
            )
        """)

        conn.commit()

        print("SmartAttend database tables created successfully!")
        print("Student registration fields are ready.")

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    create_tables()