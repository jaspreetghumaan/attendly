"""Database access for Attendly.

Two backends, chosen by ATTENDLY_DATABASE_URL (see config.py):
  * not set          -> local SQLite file (smartattend.db)
  * postgresql://... -> PostgreSQL, e.g. Supabase

The rest of the app calls execute / fetchone / fetchall / commit / rollback
exactly the same way for both. create_tables() is safe to run on every start:
it only adds what is missing, so existing data is never deleted.
"""
import logging
import re
import sqlite3

import config

log = logging.getLogger("attendly.db")

DATABASE_URL = config.DATABASE_URL
USE_POSTGRES = DATABASE_URL.lower().startswith(("postgres://", "postgresql://"))

if USE_POSTGRES:
    import psycopg
    IntegrityError = psycopg.IntegrityError
else:
    IntegrityError = sqlite3.IntegrityError

DATABASE_NAME = str(config.DATABASE_PATH)

# Named parameters look like :name in our SQL. PostgreSQL wants %(name)s.
_NAMED = re.compile(r"(?<![:\w]):([A-Za-z_]\w*)")


class Row(tuple):
    """One result row. Works like sqlite3.Row: row[0] or row["column"]."""

    def __new__(cls, values, names):
        obj = super().__new__(cls, values)
        obj._names = names
        return obj

    def __getitem__(self, key):
        if isinstance(key, str):
            return tuple.__getitem__(self, self._names[key])
        return tuple.__getitem__(self, key)

    def keys(self):
        return list(self._names)


# ---------------------------------------------------------------------------
# SQLite (local file)
# ---------------------------------------------------------------------------
class _SqliteConnection:
    def __init__(self):
        self._conn = sqlite3.connect(DATABASE_NAME, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 10000")

    def execute(self, sql, params=()):
        return self._conn.execute(sql, params)

    def begin_write(self):
        """Take the write lock now, so two requests cannot both pass a check."""
        self._conn.execute("BEGIN IMMEDIATE")

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


# ---------------------------------------------------------------------------
# PostgreSQL (Supabase)
# ---------------------------------------------------------------------------
def _pg_sql(sql, params):
    """Translate our SQLite-style placeholders into PostgreSQL ones."""
    if isinstance(params, dict):
        return _NAMED.sub(lambda m: "%(" + m.group(1) + ")s", sql)
    if params is not None:
        return sql.replace("?", "%s")
    return sql


class _PgCursor:
    def __init__(self, cursor, lastrowid=None):
        self._cur = cursor
        self.lastrowid = lastrowid

    @property
    def rowcount(self):
        return self._cur.rowcount

    def _names(self):
        if not self._cur.description:
            return {}
        return {col.name: i for i, col in enumerate(self._cur.description)}

    def fetchone(self):
        row = self._cur.fetchone()
        return None if row is None else Row(row, self._names())

    def fetchall(self):
        names = self._names()
        return [Row(row, names) for row in self._cur.fetchall()]


class _PgConnection:
    def __init__(self):
        # prepare_threshold=None: Supabase's connection pooler does not support
        # server-side prepared statements.
        self._conn = psycopg.connect(DATABASE_URL, prepare_threshold=None, connect_timeout=10)

    def execute(self, sql, params=None):
        sql = _pg_sql(sql, params)

        # SQLite gives lastrowid automatically. PostgreSQL needs RETURNING id.
        is_insert = re.match(r"\s*INSERT\b", sql, re.IGNORECASE) is not None
        wants_id = (
            is_insert
            and not re.search(r"\bRETURNING\b", sql, re.IGNORECASE)
            and "login_attempts" not in sql.lower()   # its primary key is the email
        )
        if wants_id:
            sql = sql.rstrip().rstrip(";") + " RETURNING id"

        cursor = self._conn.cursor()
        cursor.execute(sql, params)

        if wants_id:
            row = cursor.fetchone()
            return _PgCursor(cursor, row[0] if row else None)
        return _PgCursor(cursor)

    def begin_write(self):
        # Transaction-level advisory lock: released automatically on commit/rollback.
        self._conn.cursor().execute("SELECT pg_advisory_xact_lock(7001)")

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_db_connection():
    """Open a connection to whichever database is configured."""
    return _PgConnection() if USE_POSTGRES else _SqliteConnection()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
def _ddl(sql):
    """Write the SQLite form once; convert the auto-number column for PostgreSQL."""
    if USE_POSTGRES:
        sql = sql.replace(
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
        )
    return sql


STUDENT_EXTRA_COLUMNS = {
    "dob": "TEXT", "gender": "TEXT", "phone": "TEXT", "alternate_phone": "TEXT",
    "department": "TEXT", "specialization": "TEXT", "year": "INTEGER",
    "semester": "INTEGER", "admission_year": "INTEGER", "section": "TEXT",
    "college": "TEXT", "address": "TEXT", "city": "TEXT", "state": "TEXT",
    "pin_code": "TEXT", "guardian_name": "TEXT", "guardian_phone": "TEXT",
    "residence_type": "TEXT",
}

TABLES = [
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('teacher', 'student'))
    )""",
    """CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        roll_number TEXT UNIQUE NOT NULL,
        course TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        attendance_date TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('Present', 'Absent')),
        FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
        UNIQUE (student_id, attendance_date)
    )""",
    """CREATE TABLE IF NOT EXISTS classes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_name TEXT NOT NULL,
        section TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE (class_name, section, created_by)
    )""",
    """CREATE TABLE IF NOT EXISTS subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_name TEXT NOT NULL,
        subject_code TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE (subject_code, created_by)
    )""",
    """CREATE TABLE IF NOT EXISTS class_subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,
        FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE,
        FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
        UNIQUE (class_id, subject_id)
    )""",
    """CREATE TABLE IF NOT EXISTS student_enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE,
        FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
        UNIQUE (class_id, student_id)
    )""",
    """CREATE TABLE IF NOT EXISTS attendance_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,
        teacher_id INTEGER NOT NULL,
        session_date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        qr_token TEXT UNIQUE,
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
        FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE,
        FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
        FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS attendance_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'Absent' CHECK (status IN ('Present', 'Absent')),
        marked_at TEXT,
        FOREIGN KEY (session_id) REFERENCES attendance_sessions(id) ON DELETE CASCADE,
        FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
        UNIQUE (session_id, student_id)
    )""",
    """CREATE TABLE IF NOT EXISTS login_attempts (
        email TEXT PRIMARY KEY,
        failed_count INTEGER NOT NULL DEFAULT 0,
        last_failed_at TEXT,
        locked_until TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )""",
]

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_records_student ON attendance_records(student_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_teacher ON attendance_sessions(teacher_id, class_id)",
    "CREATE INDEX IF NOT EXISTS idx_enroll_student ON student_enrollments(student_id)",
    "CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id)",
]


def create_tables():
    """Create missing tables, columns and indexes. Existing data is preserved."""
    conn = get_db_connection()
    try:
        if not USE_POSTGRES:
            # WAL lets the live QR page read while students are writing.
            conn.execute("PRAGMA journal_mode = WAL")

        for statement in TABLES:
            conn.execute(_ddl(statement))

        # Extra registration columns (added to databases created before they existed)
        if USE_POSTGRES:
            for name, col_type in STUDENT_EXTRA_COLUMNS.items():
                conn.execute(f"ALTER TABLE students ADD COLUMN IF NOT EXISTS {name} {col_type}")
        else:
            existing = {row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()}
            for name, col_type in STUDENT_EXTRA_COLUMNS.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE students ADD COLUMN {name} {col_type}")

        for statement in INDEXES:
            conn.execute(statement)

        if not USE_POSTGRES and conn.execute("PRAGMA foreign_key_check").fetchall():
            raise sqlite3.IntegrityError("Database foreign-key validation failed.")

        conn.commit()
        log.info("Database schema is up to date (%s).", "PostgreSQL" if USE_POSTGRES else "SQLite")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    create_tables()
    print("Attendly database setup completed successfully!")