"""Check that Attendly can reach the configured database (SQLite or Supabase).

Run:  python check_connection.py
"""
import database


def main():
    backend = "PostgreSQL (Supabase)" if database.USE_POSTGRES else "SQLite (local file)"
    print("Database backend:", backend)

    try:
        database.create_tables()
        print("Tables: OK")

        conn = database.get_db_connection()
        try:
            ok = conn.execute("SELECT 1 AS ok").fetchone()["ok"]
            users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        finally:
            conn.close()

        print("Connection: OK" if ok == 1 else "Connection: unexpected answer")
        print(f"Accounts in database: {users}")
    except Exception as error:
        print("\nCould not connect.")
        print("Error:", type(error).__name__, "-", error)
        if database.USE_POSTGRES:
            print("\nCheck that ATTENDLY_DATABASE_URL is the full connection string from Supabase,")
            print("with the correct password, and that your internet connection is working.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()