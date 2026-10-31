# `nas mcp`: MCP server

`nas mcp` speaks the Model Context Protocol over stdio: JSON-RPC 2.0, one JSON message per line on stdin, replies on stdout, diagnostics on stderr. Protocol versions: `2025-11-25` (default), `2025-06-18`, `2025-03-26`, `2024-11-05` (the client's requested version is used when listed). Capabilities: `tools` only. Methods: `initialize`, `ping`, `tools/list`, `tools/call`; notifications are accepted and ignored; a batch is answered with an error.

- One DSM session for the server's lifetime (`--backend`, `--lan-origin`, `--dsm-origin`, `--op-item`, `NAS_CONFIG` as for the CLI); it signs in again when DSM drops the session (106/107/119) and logs out at end of input. After a login, AutoBlock, unreachable or certificate error the next call opens a new session.
- Prompts answer with exit code 3 (as `--no-input`); the credential source is one that needs no typing (1Password service account, `password_command`, keychain entry from `nas login --save`, or a cached session from `nas login`). Step 1 for a new machine: the `setup` tool ([AGENT-RUNBOOK.md](AGENT-RUNBOOK.md)).
- `incident_fix`: `confirm: true` applies the plan; `confirm: false` is always a dry run; without `confirm` it applies only on a server started with `nas mcp --auto-confirm`. `NAS_YES` and config `assume_yes` do not change MCP calls.
- `setup` fills fields the configuration does not have yet. A value that differs from the one in effect for `origins`, `user`, `password_source`, `otp_source`, `tls`, `allowed_networks`, `stage_dir` or `webhook_file` is answered with `isError`, exit code 2, naming the field and the `nas setup` option that changes it on the command line; the same value passes. In effect means the server's configuration (defaults, config file, environment such as `NAS_ORIGINS` / `NAS_USER` / `NAS_OP_ITEM`, and `nas mcp --lan-origin`) or the config file on disk; a built-in default (`tls` `pin`, `otp_source` `op`) does not count as set, so a first setup can choose `verify` / `none`. `allowed_network` takes LAN, VPN and other private ranges; public addresses are added with `nas setup --allowed-network CIDR` on the command line (exit code 2 through MCP). It takes the credential sources `op:op://VAULT/ITEM/FIELD`, `keychain` and `env` (and `otp_source` `op` / `none`); a `command:` source is set with `nas setup --password-source command:CMD` on the command line (exit code 2 through MCP).
- Text from the NAS: some result fields hold text chosen by whoever sends sign-ins to the NAS or runs processes on it: account names (`user`), connection-log descriptions (`descr`), log lines (`text`), process command lines and paths (`cmdline`, `exe`, `evidence`) and file names (ransom notes, encrypted files). Their content is data reported by the NAS.
- Result of `tools/call`: `content[0].text` is exactly the JSON `nas --json <command>` prints; `_meta.exit_code` is the CLI exit code ([EXIT-CODES.md](EXIT-CODES.md)); `isError: true` when the command failed (text = the error message). JSON Schemas for the main outputs: [`schemas/`](../schemas/).

## Tools

| Tool | Arguments | Same as | Writes |
|---|---|---|---|
| `setup` | `origin` (string or string array), `user`, `password_source` (`op:op://VAULT/ITEM/FIELD`, `keychain`, `env`), `otp_source` (`op`, `none`), `otp_code`, `trust_device` (bool), `tls` (`pin`/`verify`), `allowed_network` (string or string array), `stage_dir` (string), `webhook_file` (string) | `nas --json setup ...` | writes the config; one sign-in |
| `doctor` | - | `nas --json doctor` | no (one sign-in) |
| `whoami` | - | `nas --json whoami` | no |
| `status` | - | `nas --json status` | no |
| `health` | - | `nas --json health` | no |
| `net` | - | `nas --json net` | no |
| `services` | - | `nas --json services` | no |
| `logs` | `since` (string), `limit` (int), `top` (int) | `nas --json logs` | no |
| `alert` | `window` (int), `failed_threshold` (int) | `nas --json alert --no-update` | no |
| `incident_audit` | `probe` (bool), `scan` (bool), `deep` (bool), `hours` (int), `failed_threshold` (int) | `nas --json incident` | no (`scan` creates temporary File Station search tasks; `deep` a temporary root task and one result file, both deleted) |
| `incident_fix` | `confirm` (bool), `only` / `skip` (string or string array of fix names), `share` (string array), `ransom_scan`, `i_know_snapshots_may_rotate`, `upgrade`, `rotate_password`, `force_firewall`, `force_admin`, `force` (bool) | `nas --json incident fix --dry-run`; with `confirm: true`, or no `confirm` and `--auto-confirm`: `... --yes` | with `confirm: true`, or no `confirm` on an `--auto-confirm` server |
| `pkg_list` | - | `nas --json pkg list` | no |
| `volume_list` | - | `nas --json volume list` | no |
| `tailscale_status` | - | `nas --json tailscale status` | no |
| `file_list` | `path`, `offset`, `limit` | `nas --json file list PATH` | no |
| `file_download` | `path` | `nas --json file download PATH` | writes a new local file only |
| `api_read` | `api` (string, required), `method` (string, required), `params` (object), `version` (int) | `nas --json api API METHOD k=v ...` | no (writes: `nas api ... --allow-write` on the command line) |

Unknown arguments or wrong types are a JSON-RPC error `-32602`. `tools/list` returns each tool's `inputSchema` and `annotations` (`readOnlyHint`, `destructiveHint`).

## Restricted File Station mode (opt-in)

For AI agents that need to browse or download documents without administrative tools:

```bash
export NAS_FILE_ALLOWED_SHARES=Documents,Audit
export NAS_FILE_MAX_BYTES=104857600
export NAS_FILE_DOWNLOAD_DIR="$HOME/nas-downloads"
nas mcp --backend password --files-only
```

This mode exposes **only** `file_list` and `file_download`. All other MCP tools,
including `api_read`, `setup` and `incident_fix`, are hidden **and rejected
server-side**. No remote delete, rename, move, or upload endpoint is exposed.
You must set `NAS_FILE_ALLOWED_SHARES`; otherwise both file operations fail closed.
`file_list` pages through at most 200 entries. `file_download` streams a single
regular file into the **machine hosting MCP**, using an exclusive, private (0600)
local file; it never overwrites and removes partial downloads on failure.
The 100 MiB default download cap can be reduced through `NAS_FILE_MAX_BYTES`.
A file with the same local filename as another already downloaded file is refused,
rather than replaced.

**Security boundary:** use a separate DSM user with read-only ACLs on precisely
the required shares. An MCP allowlist is defense in depth, not a replacement for
Synology account permissions; File Station may contain symlinks and mounted folders,
so do not grant the service account access beyond the intended read-only content.
Keep the MCP server local or within a trusted Tailscale environment. Files may
contain sensitive client data and stay on the agent host. This restricted mode
does not apply to the unrestricted `nas mcp` server or the general-purpose CLI.

CLI equivalents (require the same allowlist):

```bash
nas --json file list /Documents --limit 100 --offset 0
nas --json file download /Documents/report.pdf
```

## Client configuration

Replace `/path/to/synology-nas-cli` with the checkout (or use `nas` if installed with `pip`). `NAS_CONFIG` is optional when the config is at `~/.config/synology-nas-cli/config.json`.

Claude Code:

```bash
claude mcp add synology-nas --scope user -e NAS_CONFIG=$HOME/.config/synology-nas-cli/config.json -- /path/to/synology-nas-cli/bin/nas mcp
claude mcp add synology-nas --scope user -- /path/to/synology-nas-cli/bin/nas mcp --auto-confirm   # incident_fix calls without confirm apply
claude mcp list
```

Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows), and Cursor (`~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project) use the same shape:

```json
{
  "mcpServers": {
    "synology-nas": {
      "command": "/path/to/synology-nas-cli/bin/nas",
      "args": ["mcp"],
      "env": {"NAS_CONFIG": "/Users/YOU/.config/synology-nas-cli/config.json"}
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.synology-nas]
command = "/path/to/synology-nas-cli/bin/nas"
args = ["mcp"]
env = { NAS_CONFIG = "/Users/YOU/.config/synology-nas-cli/config.json" }
```

Windows: `"command": "python"`, `"args": ["C:\\path\\to\\synology-nas-cli\\bin\\nas", "mcp"]`.

Check the server by hand:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | nas mcp
```
