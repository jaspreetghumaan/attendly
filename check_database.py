#Database integrity check script for the QR Attendance System
import sqlite3

conn = sqlite3.connect("smartattend.db")

try:
    print("=== Student Foreign Keys ===")

    foreign_keys = conn.execute(
        "PRAGMA foreign_key_list(students)"
    ).fetchall()

    for key in foreign_keys:
        print(key)

    print("\n=== Database Tables ===")

    tables = conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
    """).fetchall()

    for table in tables:
        print(table[0])

    print("\n=== Foreign Key Violations ===")

    violations = conn.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()

    if violations:
        for violation in violations:
            print(violation)
    else:
        print("No violations found.")

finally:
    conn.close()