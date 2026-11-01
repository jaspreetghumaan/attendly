import sqlite3
import shutil
from pathlib import Path

DB_PATH = Path("smartattend.db")
BACKUP_PATH = Path(
    "database_backup/smartattend_before_role_cleanup.db"
)


def migrate_roles():
    if not DB_PATH.exists():
        print("ERROR: Database not found.")
        return

    if not BACKUP_PATH.exists():
        print("ERROR: Database backup not found.")
        return

    # Create an additional backup without overwriting existing backups.
    extra_backup = Path(
        "database_backup/smartattend_before_role_cleanup_extra.db"
    )

    if not extra_backup.exists():
        shutil.copy2(DB_PATH, extra_backup)

    conn = sqlite3.connect(DB_PATH)

    try:
        # Verify the database before making changes.
        violations = conn.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        if violations:
            print("ERROR: Existing foreign-key violations found.")
            print(violations)
            return

        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN")

        # Convert existing Admin accounts into Teacher accounts.
        conn.execute("""
            UPDATE users
            SET role = 'teacher'
            WHERE role = 'admin'
        """)

        # Create the replacement users table.
        conn.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('teacher', 'student'))
            )
        """)

        # Preserve all existing account information.
        conn.execute("""
            INSERT INTO users_new (
                id, name, email, password, role
            )
            SELECT id, name, email, password, role
            FROM users
        """)

        # Replace the old users table.
        conn.execute("DROP TABLE users")
        conn.execute(
            "ALTER TABLE users_new RENAME TO users"
        )

        # Verify the role values before committing.
        roles = conn.execute("""
            SELECT role, COUNT(*)
            FROM users
            GROUP BY role
        """).fetchall()

        print("Roles after migration:")
        for role, count in roles:
            print(f"{role}: {count}")

        invalid_roles = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role NOT IN ('teacher', 'student')
        """).fetchone()[0]

        if invalid_roles:
            raise RuntimeError("Unexpected role found.")

        # Check foreign keys before committing.
        violations = conn.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        if violations:
            raise RuntimeError(
                f"Foreign-key violations: {violations}"
            )

        # Commit only if all checks pass.
        conn.commit()
        print("\nSUCCESS: Admin role removed from the database.")
        print("Existing user IDs and account data were preserved.")
        print("Foreign-key check passed.")

    except Exception as error:
        conn.rollback()
        print("\nMigration failed:", error)
        print("Changes were rolled back.")

    finally:
        conn.close()


if __name__ == "__main__":
    migrate_roles()