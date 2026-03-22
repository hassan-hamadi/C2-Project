# C2 Framework

> **Full technical breakdown available:** For the complete architecture review, engineering decisions, and OPSEC autopsy of every detection surface in this framework, read the blog post: [coming soon..](/blog/c2-development-from-scratch-phase-1-teardown).

## Disclaimer

This is an educational and authorized security research tool. It is a Phase 1 Alpha build with intentionally documented detection surfaces. Do not deploy this outside of lab environments you own or have explicit written authorization to test. The accompanying blog post details every IOC this framework generates and exactly how a Blue Team would catch it.

## Overview

A command and control framework built from scratch to understand C2 communication at the implementation level. The framework uses a pull-based HTTP polling model with a Go agent and a Python/Flask team server.

The agent is a statically linked Go binary with zero external dependencies. It checks in on a configurable interval, retrieves pending tasks, executes them, and reports results. The server compiles agents on demand with operator-specified configuration (callback URL, check-in interval, persistence) injected directly into the Go source as compile-time literals. There is no config file on disk.

This is an Alpha build. It is not OPSEC-safe and was never intended to be. It generates significant behavioral artifacts that are trivially detectable by EDR, network monitoring, and basic forensic triage. Every one of those artifacts is documented in the blog post above.

## Architecture

```
Operator (Dashboard)
        │
        │  HTTP
        ▼
┌──────────────────┐
│   Team Server    │
│  (Python/Flask)  │
│                  │
│  - REST API      │
│  - Task Queue    │
│  - Payload       │
│    Builder       │
│  - SQLite DB     │
└────────┬─────────┘
         │
         │  HTTP Polling (JSON)
         │
    ┌────┴────┬──────────┐
    ▼         ▼          ▼
 Agent     Agent      Agent
  (Go)      (Go)       (Go)
```

## Current State (Phase 1)

### Agent

| Capability | Implementation |
|---|---|
| HTTP Beaconing | Fixed-interval polling via `time.Sleep`. Agent POSTs identity, receives task array. |
| Command Execution | Dispatches to `cmd.exe /C` (Windows) or `/bin/sh -c` (Linux/macOS) per task. |
| Stateful `cd` | Intercepts `cd` commands before the shell. Tracks working directory in-process via a `CurrentDir` global. Subsequent commands inherit it through `cmd.Dir`. |
| File Exfiltration | `get <path>` reads target file and POSTs as `multipart/form-data` to the server. |
| File Drop | `download <id> <path>` fetches a staged file from the server and writes to disk. |
| Persistence | Windows: `reg.exe add` to `HKCU\...\Run`. Linux: `@reboot` cron entry. |
| Self-Destruct | Removes persistence, deletes own binary (Linux: `os.Remove`, Windows: deferred `.bat` cleanup script), purges all agent data from the server database. |
| Identity | Cryptographically random UUID v4 via `crypto/rand`, generated at launch. Ephemeral: new UUID on every restart. |

### Server

| Capability | Implementation |
|---|---|
| Dynamic Compilation | Generates custom `config.go` and `main.go`, cross-compiles via `go build` with `GOOS`/`GOARCH` targeting. Strips symbols with `-s -w` ldflags. Windows builds use `-H=windowsgui` to suppress the console. |
| Task Queue | SQLite-backed state machine: `pending` > `sent` > `complete`. Tasks are bundled into the check-in response and marked `sent` on retrieval. |
| Loot Storage | Exfiltrated files saved with timestamp prefix. Metadata recorded in `loot` table. |
| File Staging | Operator uploads files via dashboard. Agent pulls by numeric ID on command. |
| Agent Management | Registration on first check-in, `last_seen` update on subsequent check-ins, cascading purge on self-destruct. |

### Known Detection Surfaces

All of these are documented in detail in the blog post. Summary:

- **Network Analysis:** Fixed-interval beaconing with zero jitter. Network analysis (RITA, Zeek) flags it immediately.
- **Process tree artifacts.** Every command spawns `cmd.exe`/`sh` as a child process. EDR process tree heuristics catch this pattern.
- **Loud persistence.** `reg.exe` writes to the most monitored registry key in Windows. The value name is a hardcoded string.
- **Plaintext HTTP.** All traffic is unencrypted with the default `Go-http-client/1.1` User-Agent. Predictable URL paths (`/api/checkin`, `/api/result`).
- **No server authentication.** Every endpoint is open. Anyone who finds the server can enumerate agents, submit tasks, or download loot.
- **String literals in binary.** API paths, server URL, and persistence names are all visible via `strings`.

## Planned Evasion (Phase 2)

**Network layer:** Jitter and beacon randomization to break frequency analysis. HTTPS with certificate pinning. AES-256-GCM payload encryption (opaque even to TLS-intercepting proxies). User-Agent spoofing and randomized API endpoint paths at build time.

**Host layer:** Direct Windows API syscalls (`FindFirstFile`, `GetUserNameW`, `RegSetValueExW`) to eliminate `cmd.exe` process trees. Stealthier persistence via COM object hijacking, `ITaskService` COM scheduled tasks, or DLL search order hijacking. In-memory payload execution to avoid writing to disk.

**Server layer:** API key authentication on all endpoints. Flask debug mode disabled. SQLite database encrypted at rest. Mutual TLS for agent-to-server verification.

## Project Structure

```
C2-Project/
├── agent/
│   ├── main.go              # Entry point, check-in loop, command dispatcher
│   ├── config.go            # Compile-time configuration, UUID generation
│   ├── go.mod
│   └── funcs/
│       ├── shell.go          # Command execution, cd state tracking
│       ├── transfer.go       # File exfiltration and download
│       ├── persist.go        # Registry/cron persistence
│       └── selfdestruct.go   # Binary deletion and DB purge
├── server/
│   ├── app.py               # Flask API, build pipeline, task management
│   ├── database.py          # SQLite schema and connection handling
│   ├── templates/
│   │   └── index.html        # Operator dashboard
│   └── static/               # Frontend assets
├── requirements.txt
└── README.md
```

## Quick Start

### Start the Server

```bash
cd server
pip install -r ../requirements.txt
python app.py
```

The dashboard is available at `http://localhost:5000`.

### Build an Agent

From the dashboard, navigate to Deploy and configure:

- **Target OS:** `windows`, `linux`, or `MacOS`
- **Architecture:** `amd64`, `arm64`, or `386`
- **Server URL:** Callback address for the agent
- **Interval:** Check-in frequency in seconds
- **Persistence:** Enable or disable boot persistence

Click Build. The server compiles the agent with the specified configuration and returns the binary for download.

Alternatively, build via the API:

```bash
curl -X POST http://localhost:5000/api/build \
  -H "Content-Type: application/json" \
  -d '{
    "target_os": "windows",
    "arch": "amd64",
    "server_url": "http://<YOUR_SERVER>:5000",
    "interval": "30",
    "persistence": false
  }'
```

### Run the Agent

Execute the compiled binary on the target host. It will generate a UUID, begin checking in at the configured interval, and appear in the dashboard.

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Operator dashboard |
| `POST` | `/api/checkin` | Agent check-in and task retrieval |
| `POST` | `/api/result` | Task result submission |
| `POST` | `/api/task` | Queue a command for an agent |
| `POST` | `/api/upload` | Receive exfiltrated file from agent |
| `POST` | `/api/build` | Compile a new agent binary |
| `GET` | `/api/agents` | List all registered agents |
| `DELETE` | `/api/agents/<id>` | Queue self-destruct for agent |
| `DELETE` | `/api/agents/<id>/force` | Force-remove agent from database |
| `GET` | `/api/tasks/<agent_id>` | Get task history for an agent |
| `GET` | `/api/results/<task_id>` | Get output for a specific task |
| `POST` | `/api/files/stage` | Upload a file for agent download |
| `GET` | `/api/files/<id>` | Agent fetches a staged file |
| `GET` | `/api/loot` | List exfiltrated files |
| `GET` | `/api/loot/download/<id>` | Download an exfiltrated file |
| `GET` | `/api/stats` | Dashboard statistics |

## License

See [LICENSE](LICENSE) for details.