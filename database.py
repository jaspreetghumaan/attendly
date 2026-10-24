#Database 
import sqlite3

import config
DATABASE_NAME = str(config.DATABASE_PATH)  # Convert Path object to string for sqlite3


def get_db_connection():
    """Connect to the Attendly SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables():
    """Create and update database tables without deleting existing data."""

    conn = get_db_connection()

    try:
        # --------------------------------------------------
        # 1. USERS TABLE
        # --------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('teacher', 'student'))
            )
        """)

        # --------------------------------------------------
        # 2. STUDENTS TABLE
        # --------------------------------------------------
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

        # --------------------------------------------------
        # 3. STUDENT REGISTRATION FIELDS
        # Add missing columns to existing databases.
        # Existing student records remain preserved.
        # --------------------------------------------------
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
                    f"ALTER TABLE students "
                    f"ADD COLUMN {column_name} {column_type}"
                )

        # --------------------------------------------------
        # 4. ATTENDANCE TABLE
        # Existing structure preserved for now.
        # Session-based attendance will be implemented later.
        # --------------------------------------------------
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

        # --------------------------------------------------
        # 5. CLASSES TABLE
        # Each teacher can create their own classes.
        # --------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_name TEXT NOT NULL,
                section TEXT NOT NULL,
                created_by INTEGER NOT NULL,

                FOREIGN KEY (created_by)
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                UNIQUE (class_name, section, created_by)
            )
        """)

        # --------------------------------------------------
        # 6. SUBJECTS TABLE
        # Each teacher can add their own subjects.
        # --------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_name TEXT NOT NULL,
                subject_code TEXT NOT NULL,
                created_by INTEGER NOT NULL,

                FOREIGN KEY (created_by)
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                UNIQUE (subject_code, created_by)
            )
        """)

        # --------------------------------------------------
        # 7. CLASS-SUBJECT MAPPING TABLE
        # Assign subjects to particular classes.
        # --------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS class_subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_id INTEGER NOT NULL,
                subject_id INTEGER NOT NULL,

                FOREIGN KEY (class_id)
                    REFERENCES classes(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (subject_id)
                    REFERENCES subjects(id)
                    ON DELETE CASCADE,

                UNIQUE (class_id, subject_id)
            )
        """)

        # Verify foreign-key relationships before committing.
        foreign_key_errors = conn.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        if foreign_key_errors:
            raise sqlite3.IntegrityError(
                "Database foreign-key validation failed."
            )

        conn.commit()

        print("Attendly database setup completed successfully!")
        print("Users and student registration tables are ready.")
        print("Classes, subjects, and class-subject tables are ready.")
        print("Existing attendance table has been preserved.")

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    create_tables()