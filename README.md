# C2 Framework

> **Full technical breakdown available:** For the complete architecture review, engineering decisions, and OPSEC autopsy of every detection surface in this framework, read the blog post: [C2 Development from Scratch: Phase 1 Teardown](https://www.hassanhamadi.me/blog/c2-development-from-scratch-phase-1-teardown).

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
| HTTP Beaconing | Range-based jitter: sleeps a random duration uniformly sampled between `JitterMin` and `JitterMax` each cycle. Agent POSTs identity, receives task array. |
| Browser Profile Spoofing | Compile-time browser profile selection. A `UATransport` RoundTripper intercepts every outbound request and injects a full, validated header set matching one of five real browser fingerprints (Chrome/Win, Chrome/Linux, Firefox/Win, Firefox/Linux, Safari/macOS). |
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
| Dynamic Compilation | Generates custom `config.go` and `main.go`, cross-compiles via `go build` with `GOOS`/`GOARCH` targeting. Strips symbols with `-s -w` ldflags. Windows builds use `-H=windowsgui` to suppress the console. Beacon timing is baked into the binary as a `JitterMin`/`JitterMax` range (no config file on disk). Browser profile ID and locale are injected at compile time. |
| Task Queue | SQLite-backed state machine: `pending` > `sent` > `complete`. Tasks are bundled into the check-in response and marked `sent` on retrieval. |
| Loot Storage | Exfiltrated files saved with timestamp prefix. Metadata recorded in `loot` table. |
| File Staging | Operator uploads files via dashboard. Agent pulls by numeric ID on command. |
| Agent Management | Registration on first check-in, `last_seen` update on subsequent check-ins, cascading purge on self-destruct. |

### Evasion Status

Tracks every known detection surface, what the fix is, and whether it has been implemented yet.

| Surface | Risk | Status | Fix |
|---|---|---|---|
| Beacon frequency | Fixed-interval polling is trivially flagged by most network analysis software | ✅ Fixed | Range-based jitter, where the agent sleeps a random duration between `JitterMin` and `JitterMax` each cycle |
| User-Agent fingerprint | Default `Go-http-client/1.1` User-Agent is a high-confidence IOC; mismatched headers create detectable "HTTP chimeras" | ✅ Fixed | Five validated browser profiles (Chrome/Win, Chrome/Linux, Firefox/Win, Firefox/Linux, Safari/macOS) applied via a `UATransport` RoundTripper. Each profile includes the correct UA string, `Sec-Ch-Ua` client hints, `Sec-Fetch-*` metadata, and `Accept` values, matching the April 2026 browser baseline |
| Process tree | Every shell command spawns `cmd.exe` or `sh` as a direct child, visible to any EDR | 🔴 Open | Direct Windows API syscalls (`CreateProcess`, `ShellExecute`) to cut out the shell middleman |
| Persistence noise | `reg.exe` writes to the most-monitored Run key in Windows with a hardcoded value name | 🔴 Open | COM object hijacking, `ITaskService` scheduled tasks, or DLL search order hijacking (or a simpler method I am still researching this topic) |
| Payload encryption | All C2 traffic payloads (commands, results) are sent as plaintext JSON, readable by any network tap | 🔴 Open | AES-256-GCM payload encryption with per-session key exchange |
| Transport security | All traffic is unencrypted HTTP, visible to any man-in-the-middle | 🔴 Open | HTTPS with certificate pinning |
| Predictable URLs | Endpoint paths (`/api/checkin`, `/api/result`) are hardcoded and easily signatured | 🔴 Open | Randomise API paths at build time via the payload builder |
| No authentication | Every server endpoint is open, anyone who finds the server can issue commands or download loot | 🔴 Open | API key auth on all endpoints, mutual TLS for agent-to-server trust |
| Strings in binary | Server URL, API paths, and persistence names are all visible via `strings` | 🔴 Open | Symbol stripping is already done (`-s -w`); compile-time obfuscation for string literals is next |

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
│       ├── selfdestruct.go   # Binary deletion and DB purge
│       └── ua.go             # Browser profile spoofing (UATransport + 5 profiles)
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
- **Jitter range:** Min and max beacon interval in seconds (agent picks randomly within the range)
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
    "jitter_min": "8",
    "jitter_max": "30",
    "persistence": false
  }'
```

### Run the Agent

Execute the compiled binary on the target host. It will generate a UUID, begin checking in at the configured jitter range, and appear in the dashboard.

## Testing

The agent package includes unit tests for the jitter implementation. Run them from the `agent/` directory.

```bash
cd agent

# Run all tests
go test ./funcs/ -v -count=1

# Run only the jitter tests
go test ./funcs/ -v -count=1 -run "TestRandomDuration|TestSleepWithJitter"
```

The `-count=1` flag bypasses Go's test result cache so each run is always fresh. This matters for the distribution test, which draws new random samples every time.

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Operator dashboard |
| `POST` | `/api/checkin` | Agent check-in and task retrieval |
| `POST` | `/api/result` | Task result submission |
| `POST` | `/api/task` | Queue a command for an agent |
| `POST` | `/api/upload` | Receive exfiltrated file from agent |
| `POST` | `/api/build` | Compile a new agent binary. Accepts `target_os`, `arch`, `server_url`, `jitter_min` (s), `jitter_max` (s), `persistence`, `profile_id` (1-5), `locale` |
| `GET` | `/api/agents` | List all registered agents |
| `GET` | `/api/agents/<id>` | _(not implemented, use DELETE variants)_ |
| `DELETE` | `/api/agents/<id>` | Queue self-destruct for agent |
| `DELETE` | `/api/agents/<id>/force` | Force-remove agent from database |
| `GET` | `/api/tasks/<agent_id>` | Get task history for an agent |
| `GET` | `/api/results/<task_id>` | Get output for a specific task |
| `GET` | `/api/builds` | List all compiled payloads |
| `GET` | `/api/builds/download/<id>` | Download a compiled agent binary |
| `DELETE` | `/api/builds/<id>` | Delete a build record and its file |
| `POST` | `/api/files/stage` | Upload a file for agent download |
| `GET` | `/api/files` | List all staged files |
| `GET` | `/api/files/<id>` | Agent fetches a staged file by ID |
| `DELETE` | `/api/files/<id>` | Delete a staged file |
| `GET` | `/api/loot` | List exfiltrated files |
| `GET` | `/api/loot/download/<id>` | Download an exfiltrated file |
| `DELETE` | `/api/loot/<id>` | Delete an exfiltrated file |
| `GET` | `/api/stats` | Dashboard statistics |

## License

See [LICENSE](LICENSE) for details.