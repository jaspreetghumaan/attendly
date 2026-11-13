import sqlite3
import shutil
from pathlib import Path

DB_PATH = Path("smartattend.db")
BACKUP_PATH = Path("smartattend_before_teacher_migration.db")

if not DB_PATH.exists():
    raise FileNotFoundError("smartattend.db not found.")

# Create an additional backup before migration.
shutil.copy2(DB_PATH, BACKUP_PATH)

conn = sqlite3.connect(DB_PATH)

try:
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("BEGIN")

    # Read the existing users table definition.
    table_info = conn.execute("""
        SELECT sql
        FROM sqlite_master
        WHERE type = 'table' AND name = 'users'
    """).fetchone()

    if not table_info:
        raise RuntimeError("Users table was not found.")

    current_sql = table_info[0]

    if "'teacher'" in current_sql:
        print("Teacher role is already supported.")
        conn.rollback()
    else:
        # Create a replacement table with all three roles.
        conn.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('admin', 'student', 'teacher'))
            )
        """)

        # Preserve all existing accounts and their IDs/password hashes.
        conn.execute("""
            INSERT INTO users_new (id, name, email, password, role)
            SELECT id, name, email, password, role
            FROM users
        """)

        conn.execute("DROP TABLE users")
        conn.execute("ALTER TABLE users_new RENAME TO users")

        conn.commit()
        print("Migration successful! Teacher role is now supported.")

except Exception:
    conn.rollback()
    raise

finally:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.close()

print(f"Backup created: {BACKUP_PATH}")