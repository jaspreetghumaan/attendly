import sqlite3

conn = sqlite3.connect("smartattend.db")
conn.row_factory = sqlite3.Row

try:
    # Show the roles currently stored in the database
    roles = conn.execute("""
        SELECT role, COUNT(*) AS total
        FROM users
        GROUP BY role
    """).fetchall()

    print("=== Existing User Roles ===")
    for row in roles:
        print(f"{row['role']}: {row['total']}")

    # Show the current users table definition
    schema = conn.execute("""
        SELECT sql
        FROM sqlite_master
        WHERE type = 'table' AND name = 'users'
    """).fetchone()

    print("\n=== Users Table Constraint ===")
    print(schema["sql"] if schema else "Users table not found.")

    # Check for foreign-key problems
    violations = conn.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()

    print("\n=== Foreign Key Check ===")
    print("No violations found." if not violations else
          [dict(row) for row in violations])

finally:
    conn.close()