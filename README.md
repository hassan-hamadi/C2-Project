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
| Browser Profile Spoofing | Compile-time browser profile selection. A `UATransport` RoundTripper intercepts every outbound request and injects a full, validated header set matching one of five real browser fingerprints (Chrome/Win, Chrome/Linux, Firefox/Win, Firefox/Linux, Safari/macOS). The transport automatically switches between navigation context (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`) for page loads and fetch context (`cors`, `empty`, `same-origin`) for JSON POST requests, matching what a real browser would send for each request type. |
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
| Dynamic Compilation | Generates custom `config.go` and `main.go`, cross-compiles via `go build` with `GOOS`/`GOARCH` targeting. Strips symbols with `-s -w` ldflags. Windows builds use `-H=windowsgui` to suppress the console. `-trimpath` removes the host build path from debug info and `-buildid=` clears the per-build hash. Beacon timing is baked into the binary as a `JitterMin`/`JitterMax` range (no config file on disk). Browser profile ID and locale are injected at compile time. |
| Task Queue | SQLite-backed state machine: `pending` > `sent` > `complete`. Tasks are bundled into the check-in response and marked `sent` on retrieval. |
| Loot Storage | Exfiltrated files saved with timestamp prefix. Metadata recorded in `loot` table. |
| File Staging | Operator uploads files via dashboard. Agent pulls by numeric ID on command. |
| Agent Management | Registration on first check-in, `last_seen` update on subsequent check-ins, cascading purge on self-destruct. |

### Evasion Status

Tracks every known detection surface, what the fix is, and whether it has been implemented yet.

| Surface | Risk | Status | Fix |
|---|---|---|---|
| Beacon frequency | Fixed-interval polling is trivially flagged by most network analysis software | ✅ Fixed | Range-based jitter, where the agent sleeps a random duration between `JitterMin` and `JitterMax` each cycle |
| User-Agent fingerprint | Default `Go-http-client/1.1` User-Agent is a high-confidence IOC; mismatched headers create detectable "HTTP chimeras". Using a placeholder version like `Chrome/147.0.0.0` is itself a fingerprinting tell, real Chrome never ships as `X.0.0.0`. Sending `Sec-Fetch-Mode: navigate` on a JSON POST is a logical impossibility that real browsers never produce | ✅ Fixed | Five validated browser profiles (Chrome/Win, Chrome/Linux, Firefox/Win, Firefox/Linux, Safari/macOS) applied via a `UATransport` RoundTripper. Each profile includes the correct UA string, `Sec-Ch-Ua` client hints, `Sec-Fetch-*` metadata, and `Accept` values matching the April 2026 browser baseline. Chrome profiles use the real stable build string (`147.0.7727.55`) and the correct `Not-A.Brand` version (`v="24"`), not the placeholder `X.0.0.0` / `v="99"` pattern that fingerprinting tools flag. The transport layer automatically switches to fetch context (`Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`, `Sec-Fetch-Site: same-origin`) on POST requests and drops navigation-only headers (`Upgrade-Insecure-Requests`, `Sec-Fetch-User`) that would be anomalous on a JSON API call |
| Process tree | Every shell command spawns `cmd.exe` or `sh` as a direct child, visible to any EDR | 🔴 Open | Direct Windows API syscalls (`CreateProcess`, `ShellExecute`) to cut out the shell middleman |
| Persistence noise | `reg.exe` writes to the most-monitored Run key in Windows with a hardcoded value name | 🔴 Open | COM object hijacking, `ITaskService` scheduled tasks, or DLL search order hijacking (or a simpler method I am still researching this topic) |
| Payload encryption | All C2 traffic payloads (commands, results) are sent as plaintext JSON, readable by any network tap | ✅ Fixed | AES-256-GCM with a per-build pre-shared key. The server generates a fresh 32-byte key at build time, injects it into the agent binary as a compile-time constant (`EncryptionKey`), and stores it in the `builds` table alongside a non-secret 8-char fingerprint (`key_id`). Every `POST /api/checkin` and `POST /api/result` body uses the `{"kid": "...", "data": "<base64(nonce+ciphertext+tag)>"}` envelope. The GCM authentication tag prevents both tampering and replay of individual messages. |
| Server response header | `Server: Werkzeug/3.x Python/3.x` response header immediately identifies the C2 server as a Flask application to any analyst inspecting traffic | ✅ Fixed | `@after_request` hook in `app.py` replaces the header with `Server: nginx/1.24.0` on every response, including error pages |
| Transport security | All traffic is unencrypted HTTP, visible to any man-in-the-middle | 🔴 Open | HTTPS with certificate pinning |
| Predictable URLs | Endpoint paths (`/api/checkin`, `/api/result`) are hardcoded and easily signatured | ✅ Fixed | The server generates a random 8-character hex slug for each of the four agent-facing endpoints (check-in, result, upload, files) at first launch and stores them in the `server_config` SQLite table. The paths persist across restarts so existing agents stay connected. At build time, all four path strings are fed through the existing XOR obfuscation pipeline and baked into the agent binary — they are never visible as plaintext in the binary, in memory, or on the wire. |
| No authentication | Every server endpoint is open, anyone who finds the server can issue commands or download loot | ✅ Fixed | A `@before_request` hook in Flask enforces a valid `X-API-Key` header on all `/api/*` requests and returns `401 Unauthorized` if it is absent or incorrect. The key is a 32-character hex string generated at first launch and stored in `server_config`. It is printed to the operator's terminal on startup. Agent-facing endpoints are naturally exempt because they live on randomised hex paths outside the `/api/` namespace. The dashboard prompts for the key on load, stores it in `sessionStorage` (wiped on tab close), and injects it as a header on every outbound API call via a centralised `apiFetch()` wrapper. |
| Function signatures | Agent functions and variables look suspicious to analysts and scanners | ✅ Fixed | Renamed all internal functions and variables to mimic benign enterprise IT software (e.g., `SyncDeviceState` instead of `checkIn`, `InstallAutoUpdater` instead of `persist`). This helps the agent blend into normal endpoint telemetry noise instead of triggering heuristics. |
| Strings in binary | Server URLs, API paths, and the persistence service name are all visible in plaintext via `strings` or Ghidra | ✅ Fixed | A random 16-byte XOR key is generated at build time by the payload builder. Every sensitive string (server URL, all API paths, the check-in sentinel, the persistence service label) is XOR-encrypted in Python, hex-encoded, and written directly into the generated `config.go` as a string literal. At runtime `funcs.ResolveConfig()` decodes them into memory on first use. Nothing sensitive appears as a printable string in the binary. |
| Build metadata / compiler footprint | Go embeds source file paths and the module name in binaries. Without extra flags, running `strings` or loading the binary in Ghidra exposes build paths like `C:\Users\<user>\Desktop\repos\C2-Project\agent\funcs\selfdestruct.go` and the original module name | ✅ Fixed | `-trimpath` strips absolute host build paths from debug info at compile time. `-buildid=` clears the per-build hash. Source files in `funcs/` were renamed to match the telemetry cover (`seal.go`, `sync_backoff.go`, `auto_updater.go`, `cache_purge.go`, `dump_sync.go`) so any residual relative paths look benign. The Go module was renamed from `c2-agent` to `endpoint-telemetry`, which is embedded in every Go binary regardless of strip flags. |

## Project Structure

```
C2-Project/
├── agent/
│   ├── main.go              # Entry point, check-in loop, command dispatcher
│   ├── config.go            # Compile-time configuration, UUID generation
│   ├── go.mod
│   └── funcs/
│       ├── seal.go              # AES-256-GCM encrypt/decrypt helpers
│       ├── config_decode.go     # XOR string decoder used at runtime
│       ├── sync_backoff.go      # Random sleep duration within a min/max range
│       ├── sync_backoff_test.go # Unit tests for jitter distribution and bounds
│       ├── shell.go             # Command execution, cd state tracking
│       ├── dump_sync.go         # File exfiltration and download
│       ├── auto_updater.go      # Registry/cron persistence
│       ├── cache_purge.go       # Binary deletion and DB purge
│       └── ua.go                # Browser profile spoofing (UATransport + 5 profiles)
├── server/
│   ├── app.py               # Flask API, build pipeline, task management
│   ├── crypto.py            # AES-256-GCM encryption, key generation
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

On first launch, the server generates a random operator API key and prints it to the terminal:

```
=======================================
  Operator API Key (paste into dashboard):
  a3f7c2e1b9d04a8f6e2c1d5b8a0f3e7c
=======================================
```

The key is stored in the SQLite database and reused on every subsequent restart. Paste it into the dashboard auth prompt when you open the UI. All operator-facing API calls require it as an `X-API-Key` header.

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
  -H "X-API-Key: <your-operator-key>" \
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

All `/api/*` endpoints require the `X-API-Key: <operator-key>` header. Agent-facing endpoints live on randomised hex paths generated at first server launch (e.g. `/a3f7c2e1`) and do not require the API key.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Operator dashboard |
| `POST` | `/<random-hex>` | Agent check-in and task retrieval (path randomised per server instance) |
| `POST` | `/<random-hex>` | Task result submission (path randomised per server instance) |
| `POST` | `/api/task` | Queue a command for an agent |
| `POST` | `/<random-hex>` | Receive exfiltrated file from agent (path randomised per server instance) |
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