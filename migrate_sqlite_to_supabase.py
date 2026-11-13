"""Copy the data in the local SQLite file (smartattend.db) into the database
set in ATTENDLY_DATABASE_URL (Supabase). Run this ONCE.

Steps:
  1. Set ATTENDLY_DATABASE_URL to your Supabase connection string.
  2. python migrate_sqlite_to_supabase.py

Ids are kept the same, so logins, classes and attendance keep working.
Rows that already exist in Supabase are skipped, so it is safe to run again.
"""
import sqlite3
import sys

import config
import database

# Parents first, so foreign keys always find their rows.
TABLES = [
    "users", "students", "classes", "subjects", "class_subjects",
    "student_enrollments", "attendance_sessions", "attendance_records",
    "password_resets", "login_attempts", "attendance",
]


def main():
    if not database.USE_POSTGRES:
        sys.exit("Set ATTENDLY_DATABASE_URL to your Supabase connection string first.")
    if not config.DATABASE_PATH.exists():
        sys.exit(f"No local database found at {config.DATABASE_PATH}. Nothing to copy.")

    database.create_tables()

    source = sqlite3.connect(config.DATABASE_PATH)
    source.row_factory = sqlite3.Row
    target = database.get_db_connection()

    try:
        for table in TABLES:
            columns = [row["name"] for row in source.execute(f"PRAGMA table_info({table})")]
            if not columns:
                print(f"{table}: not in the local database, skipped")
                continue

            rows = source.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall()
            placeholders = ", ".join("?" for _ in columns)
            copied = 0
            for row in rows:
                cursor = target.execute(
                    f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
                    f"ON CONFLICT DO NOTHING",
                    tuple(row),
                )
                copied += cursor.rowcount

            # Let new rows in Supabase continue after the largest copied id.
            if "id" in columns:
                target.execute(
                    f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                    f"COALESCE((SELECT MAX(id) FROM {table}), 1), "
                    f"(SELECT MAX(id) FROM {table}) IS NOT NULL)"
                )
            print(f"{table}: {len(rows)} found locally, {copied} copied")

        target.commit()
        print("\nMigration finished. Run 'python check_connection.py' and then 'python app.py'.")
    except Exception:
        target.rollback()
        raise
    finally:
        target.close()
        source.close()


if __name__ == "__main__":
    main()