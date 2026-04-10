import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2.db")


def get_db_connection():
    """Return a database connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create the database tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            ip TEXT,
            os TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            command TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            output TEXT,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES tasks(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS builds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            target_os TEXT NOT NULL,
            arch TEXT NOT NULL,
            server_url TEXT NOT NULL,
            callback_interval TEXT NOT NULL,
            persistence INTEGER DEFAULT 0,
            file_path TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            key_id TEXT,
            encryption_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Add type column to tasks table (safe to re-run, ignores if it exists)
    try:
        cursor.execute("ALTER TABLE tasks ADD COLUMN type TEXT DEFAULT 'shell'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add columns for encryption key storage (safe to re-run, ignores if they exist)
    for _col, _coltype in [("key_id", "TEXT"), ("encryption_key", "TEXT"), ("cert_pin", "TEXT")]:
        try:
            cursor.execute(f"ALTER TABLE builds ADD COLUMN {_col} {_coltype}")
        except sqlite3.OperationalError:
            pass  # Column already exists

    # Migrate old boolean persistence values (0/1) to method strings
    try:
        cursor.execute("UPDATE builds SET persistence = 'registry' WHERE persistence = '1'")
        cursor.execute("UPDATE builds SET persistence = 'none' WHERE persistence = '0'")
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS loot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_path TEXT,
            file_path TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS staged_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS server_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Initialize database at import time
init_db()
