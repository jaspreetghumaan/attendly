import sqlite3


def get_db_connection():
    conn = sqlite3.connect("smartattend.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables():
    conn = get_db_connection()

    try:
               # Classes table
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

        # Subjects table
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

        # Subjects assigned to classes
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