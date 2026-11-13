"""Database connection and schema for Attendly (SQLite).

create_tables() is safe to run on every start. It only adds what is missing,
so existing data is never deleted.
"""
import logging
import sqlite3

import config

DATABASE_NAME = str(config.DATABASE_PATH)

log = logging.getLogger("attendly.db")


def get_db_connection():
    """Open a connection with foreign keys on and a wait for locked databases."""
    conn = sqlite3.connect(DATABASE_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def create_tables():
    """Create missing tables and columns. Existing data is preserved."""
    conn = get_db_connection()

    try:
        # WAL lets the live QR page read while students are writing.
        conn.execute("PRAGMA journal_mode = WAL")

        # 1. USERS (both students and teachers)
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

        # 2. STUDENTS
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

        # 3. Extra student registration columns (added to old databases)
        existing_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(students)").fetchall()
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
            "residence_type": "TEXT",
        }
        for column_name, column_type in new_columns.items():
            if column_name not in existing_columns:
                conn.execute(
                    f"ALTER TABLE students ADD COLUMN {column_name} {column_type}"
                )

        # 4. LEGACY ATTENDANCE TABLE (kept so old data is not lost)
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

        # 5. CLASSES (each teacher has their own)
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

        # 6. SUBJECTS (each teacher has their own)
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

        # 7. CLASS <-> SUBJECT
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

        # 8. STUDENT ENROLLMENTS (which student is in which class)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS student_enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,

                FOREIGN KEY (class_id)
                    REFERENCES classes(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (student_id)
                    REFERENCES students(id)
                    ON DELETE CASCADE,

                UNIQUE (class_id, student_id)
            )
        """)

        # 9. ATTENDANCE SESSIONS (one class period, one rotating QR)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attendance_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_id INTEGER NOT NULL,
                subject_id INTEGER NOT NULL,
                teacher_id INTEGER NOT NULL,
                session_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                qr_token TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'closed')),

                FOREIGN KEY (class_id)
                    REFERENCES classes(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (subject_id)
                    REFERENCES subjects(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (teacher_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        # 10. ATTENDANCE RECORDS (one row per student per session)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attendance_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Absent'
                    CHECK (status IN ('Present', 'Absent')),
                marked_at TEXT,

                FOREIGN KEY (session_id)
                    REFERENCES attendance_sessions(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (student_id)
                    REFERENCES students(id)
                    ON DELETE CASCADE,

                UNIQUE (session_id, student_id)
            )
        """)

        # 11. LOGIN LOCKOUT (per email, see security.py)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                email TEXT PRIMARY KEY,
                failed_count INTEGER NOT NULL DEFAULT 0,
                last_failed_at TEXT,
                locked_until TEXT
            )
        """)

        # 12. PASSWORD RESET TOKENS (only a hash of each token is stored)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
        """)

        # Indexes for the lookups the app runs on every page
        conn.execute("CREATE INDEX IF NOT EXISTS idx_records_student ON attendance_records(student_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_teacher ON attendance_sessions(teacher_id, class_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_enroll_student ON student_enrollments(student_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id)")

        # Verify foreign-key relationships before committing.
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise sqlite3.IntegrityError("Database foreign-key validation failed.")

        conn.commit()
        log.info("Database schema is up to date.")

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    create_tables()
    print("Attendly database setup completed successfully!")
