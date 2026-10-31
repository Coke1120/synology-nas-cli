"""Argument parsing and output for `nas`."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import traceback

from . import __version__, alert, commands, config, files, incident, manage, onboard, selfmon, upgrade
from .backends import NasError, PasswordBackend, open_session
from .errors import set_no_input
from .credentials import Credentials

COMMANDS = {
    "setup": (None, "write the config and sign in once; reports missing information as JSON (exit 3)"),
    "doctor": (None, "check config, credentials, origin, TLS, login, DSM version, 2FA, capabilities, clock"),
    "whoami": (commands.whoami, "log in and show backend, origin, credential source, account, admin flag, DSM version"),
    "status": (commands.status, "model, DSM version, uptime, SA-26:13 verdict"),
    "net": (commands.net, "interfaces, PPPoE, firewall"),
    "services": (commands.services, "SSH/FTP/SMB/AFP/NFS/rsync/QuickConnect/AutoBlock"),
    "inventory": (commands.inventory, "shares, packages (SA-26:14), containers, users, scheduled tasks"),
    "ransom-scan": (commands.ransom_scan, "search all shares for .L0CK3D / read-me3.txt"),
    "exposure": (commands.exposure, "TCP probe of the LAN and public addresses from this machine"),
    "health": (commands.health, "disks/SMART/temps, pools, volumes, UPS, CPU and memory"),
    "logs": (commands.logs, "connection-log summary: failed sign-ins, external successful sign-ins"),
    "incident": (incident.incident, "C3RB3R/.L0CK3D audit (read-only); `incident fix` applies the hardening"),
    "upgrade": (upgrade.upgrade, "DSM manual update: download .pat, upload, PreCheck, install with --yes"),
    "pkg": (manage.pkg, "packages: list | start ID | stop ID | install ID | uninstall ID | default-volume [VOL]"),
    "volume": (manage.volume, "volumes: list | atime VOLUME_ID {noatime|relatime}"),
    "tailscale": (manage.tailscale, "Tailscale package: status | login-url"),
    "alert": (alert.alert, "health/security checks for a scheduler; exit 1 when something needs attention"),
    "alert-deploy": (selfmon.deploy, "run `alert --push` on the NAS itself (root task every N min) and point "
                                     "DSM's notification webhook at the same URL"),
    "login": (None, "log in once and cache the DSM session; --save stores the password in the OS keychain"),
    "logout": (None, "end the cached session; --forget also removes the keychain entry and trusted-device token"),
    "config": (None, "config init (write an example file) | config show (effective config, secrets masked)"),
    "trust": (None, "list the DSM certificates trusted on first use; --reset ORIGIN forgets one"),
    "mcp": (None, "Model Context Protocol server on stdin/stdout (for AI agents; see docs/MCP.md)"),
    "file": (None, "read-only File Station list | download (requires NAS_FILE_ALLOWED_SHARES)"),
    "api": (commands.raw_api, "raw DSM API call (writes need --allow-write)"),
}

EPILOGS = {
    "incident": """contain (first response while files are being encrypted):
  nas incident contain                 list candidate encryptor processes (known names, executables in
                                       /tmp, /dev/shm, /volume*/@tmp, *.L0CK3D / read-me3.txt files open
                                       for writing, high CPU outside Synology paths,
                                       incident.ioc_process_names). Executables under Synology paths need
                                       a reason besides the open files. PID 1, kernel threads and the
                                       scanning script with its parents are never signalled.
  nas incident contain --yes           SIGSTOP each candidate whose start time and executable still
                                       match the scan; verify every thread is stopped (T); D =
                                       waiting on I/O, check again. Memory and keys stay in place for a
                                       memory capture (https://github.com/soimy/c3rb3r-rescue)
  --pid N (repeatable)                 add explicit PIDs (same exclusions; a note for Synology paths)
  --stop-sync                          also stop the running Cloud Sync, Synology Drive, Hyper Backup and
                                       Container Manager packages (every container stops with Container
                                       Manager); the stopped ones are recorded for --release
  --save-exe DIR                       copy each candidate's executable into DIR on the NAS (root-only, 700)
  --release                            SIGCONT the PIDs the last freeze recorded; start paused packages
Runs as root through a temporary Task Scheduler task (--backend password, needs deploy.stage_dir) or
directly with --backend local. JSON: schemas/incident-contain.schema.json.

rescue (memory capture and key recovery with https://github.com/soimy/c3rb3r-rescue, fetched at
incident.rescue_commit):
  nas incident rescue --yes --capture-dir /usbshare1/rescue
        contain -> clone + verify the toolkit -> capture_process_memory.py for each frozen PID (as root,
        into a new case folder; refused on the volume holding the encrypted data, override
        --force-same-volume) -> download -> venv (pip --require-hashes) + self-tests
        -> recover_process_key.py candidates. --force-unverified-key, --force-unpinned-toolkit; --force = all
  ... --sample /share/file.L0CK3D [--expected-sha256 HEX]   test every candidate on a copy
  ... --decrypt-from /share/folder --decrypt-to /mnt/usb/out  decrypt copies with the verified candidate
  --workdir DIR keeps state.json; the same command continues where it stopped. --keep-on-nas stops after
  the capture. JSON: schemas/incident-rescue.schema.json.""",
}

NO_SESSION = ("config", "login", "logout", "trust", "mcp", "setup", "doctor")


def build_parser() -> argparse.ArgumentParser:
    cfg = config.get()
    p = argparse.ArgumentParser(prog="nas", description="CLI for a Synology NAS (DSM 7) and the C3RB3R/.L0CK3D "
                                "incident. Config: " + (config.loaded_from() or "built-in defaults") + ".")
    p.add_argument("--version", action="version", version=f"nas {__version__}")
    p.add_argument("--backend", choices=["chrome", "password", "local"], default=config.default_backend(),
                   help="password: log in over HTTPS with the credential chain (default); chrome: reuse a logged-in "
                        "DSM tab in Google Chrome (macOS); local: on the NAS as root, via synowebapi (no login)")
    p.add_argument("--origin", action="append",
                   help="DSM origin of the Chrome tab (repeatable; default: chrome_origins from the config)")
    p.add_argument("--lan-origin", "--dsm-origin", dest="lan_origin", action="append",
                   help="origin(s) for --backend password, tried in order (repeatable or comma-separated; default: "
                        + (", ".join(cfg["origins"]) or "origins from the config") + ")")
    p.add_argument("--op-item", help="1Password item op://VAULT/ITEM with fields username/password "
                                     "(overrides credentials.op_username/op_password)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-input", action="store_true",
                   help="answer prompts with exit code 3 instead of waiting (also NAS_NO_INPUT=1, and automatic when "
                        "stdin is not a terminal)")
    p.add_argument("--yes", dest="global_yes", action="store_true",
                   help="accept every confirmation (also NAS_YES=1 or config assume_yes)")
    p.add_argument("--force", dest="global_force", action="store_true",
                   help="apply every override at once (--force-firewall, --force-admin, snapshot rotation, reinstall)")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")
    for name, (_, help_text) in COMMANDS.items():
        sp = sub.add_parser(name, help=help_text, description=help_text, epilog=EPILOGS.get(name),
                            formatter_class=argparse.RawDescriptionHelpFormatter)
        if name == "ransom-scan":
            sp.add_argument("--timeout", type=int, default=3600, help="give up polling after N seconds")
            sp.add_argument("--pattern", help="override the glob list (comma-separated, one search task each), "
                                              "e.g. '*.html' as a positive control")
        if name == "exposure":
            sp.add_argument("--probe-timeout", type=float, default=1.5, help="seconds per TCP connect")
        if name == "logs":
            sp.add_argument("--since", help="only entries at/after this time: YYYY-MM-DD or 'YYYY-MM-DD HH:MM'")
            sp.add_argument("--limit", type=int, default=20000, help="max entries to fetch (newest first)")
            sp.add_argument("--top", type=int, default=10, help="how many users/IPs to list")
        if name == "upgrade":
            sp.add_argument("--pat", help="use this .pat instead of downloading the latest official one")
            sp.add_argument("--dry-run", action="store_true", help="only show current/target versions")
            sp.add_argument("--yes", action="store_true", help="install after PreCheck (the NAS reboots)")
            sp.add_argument("--force", action="store_true", help="proceed even if already on the latest build")
            sp.add_argument("--wait-only", action="store_true",
                            help="just wait until DSM is back and dsm_upgrade_all_done is true")
            sp.add_argument("--download-dir", default=config.path(cfg["upgrade"]["cache_dir"]),
                            help="where downloaded .pat files go")
            sp.add_argument("--lang", default=cfg["upgrade"]["lang"], help="language of PreCheck notes (enu, cht, ...)")
            sp.add_argument("--timeout", type=int, default=3600, help="seconds to wait for the reboot")
        if name == "pkg":
            sp.add_argument("action", choices=["list", "start", "stop", "install", "uninstall", "default-volume"])
            sp.add_argument("pkg_id", nargs="?", metavar="ID", help="package ID (for default-volume: /volumeN)")
            sp.add_argument("--volume", help="install: target volume (default: Package Center default)")
            sp.add_argument("--remove-data", action="store_true",
                            help="uninstall: tick the wizard's 'also delete data' options")
            sp.add_argument("--timeout", type=int, default=900, help="seconds to wait for the operation")
        if name == "volume":
            sp.add_argument("action", choices=["list", "atime"])
            sp.add_argument("volume_id", nargs="?", metavar="VOLUME_ID", help="e.g. volume_1")
            sp.add_argument("mode", nargs="?", choices=["noatime", "relatime"])
        if name == "tailscale":
            sp.add_argument("action", choices=["status", "login-url"])
            sp.add_argument("--timeout", type=int, default=60, help="seconds to wait for /api/up")
            sp.add_argument("--force", action="store_true", help="login-url: reauthenticate even if Running")
        if name == "alert":
            sp.add_argument("--state", default=alert.default_state(), help="baseline/state file")
            sp.add_argument("--window", type=int, default=60, help="minutes of connection log to look at")
            sp.add_argument("--since", help="log window start instead of --window: 'YYYY-MM-DD HH:MM'")
            sp.add_argument("--failed-threshold", type=int, default=20, help="failed sign-ins in the window")
            sp.add_argument("--log-limit", type=int, default=5000, help="max log entries to fetch")
            sp.add_argument("--no-update", action="store_true", help="don't write the state file")
            sp.add_argument("--key-days", type=int, default=14, help="warn when the Tailscale key expires within N days")
            sp.add_argument("--push", metavar="FILE",
                            help='JSON {"url", "header"} of a webhook: POST only what changed since the last push '
                                 "(push state: <state>-pushed.json)")
        if name == "alert-deploy":
            sp.add_argument("--interval", type=int, choices=[1, 5, 10, 15, 20, 30],
                            help="minutes between runs on the NAS (default: deploy.interval_min)")
            sp.add_argument("--webhook-item", metavar="op://VAULT/ITEM",
                            help="1Password item: website = webhook URL, field `header` (default: the webhook section "
                                 "of the config)")
            sp.add_argument("--no-dsm-webhook", action="store_true",
                            help="leave DSM's notification webhook alone")
            sp.add_argument("--test", action="store_true",
                            help="send DSM's test notification through the webhook")
        if name == "incident":
            sp.add_argument("action", nargs="?", choices=["fix", "contain", "rescue"],
                            help="fix: apply the hardening (see --dry-run); contain: freeze encryptor processes; "
                                 "rescue: capture their memory and recover the file key (c3rb3r-rescue)")
            sp.add_argument("--probe", action="store_true", help="TCP-probe the public address from this machine")
            sp.add_argument("--probe-timeout", type=float, default=1.5, help="seconds per TCP connect")
            sp.add_argument("--scan", action="store_true", help="search every share for ransom notes (minutes)")
            sp.add_argument("--deep", action="store_true",
                            help="indicators of compromise: one read-only root script (temporary Task Scheduler "
                                 "task, or directly with --backend local) checks logs, cron, files, users, SSH keys, "
                                 "processes and outbound connections")
            sp.add_argument("--scan-timeout", type=int, default=3600, help="give up the scan after N seconds")
            sp.add_argument("--log-limit", type=int, default=10000, help="connection-log entries to read")
            sp.add_argument("--hours", type=int, default=24, help="window for the failed sign-in count")
            sp.add_argument("--failed-threshold", type=int, default=20, help="failed sign-ins that make a WARN")
            c = sp.add_argument_group("incident contain")
            c.add_argument("--pid", type=int, action="append", help="freeze this PID too (repeatable)")
            c.add_argument("--release", action="store_true", help="SIGCONT the PIDs of the last freeze; restart "
                                                                   "packages paused with --stop-sync")
            c.add_argument("--stop-sync", action="store_true",
                           help="also stop the running Cloud Sync, Synology Drive, Hyper Backup and Container Manager "
                                "packages (every container stops with Container Manager); --release starts the "
                                "packages it stopped")
            c.add_argument("--save-exe", metavar="DIR", help="copy each candidate's executable into DIR on the NAS "
                                                             "(created root-only, mode 700)")
            c.add_argument("--cpu-threshold", type=float, default=50.0,
                           help="average CPU %% that makes a process outside Synology paths a candidate")
            r = sp.add_argument_group("incident rescue")
            r.add_argument("--workdir", metavar="DIR", help="local work folder (state.json; run again to continue); "
                                                            "default ~/.local/share/synology-nas-cli/rescue/<time>")
            r.add_argument("--no-contain", action="store_true", help="skip the freeze (processes already stopped)")
            r.add_argument("--rescue-dir", metavar="PATH", help="an existing c3rb3r-rescue checkout")
            r.add_argument("--capture-dir", metavar="NAS_FOLDER",
                           help="File Station folder for the memory capture, on a USB disk or another volume "
                                "(e.g. /usbshare1/rescue)")
            r.add_argument("--keep-on-nas", action="store_true", help="stop after the capture; leave it on the NAS")
            r.add_argument("--sample", metavar="NAS_FILE", help="encrypted file to test the candidates on (a copy)")
            r.add_argument("--expected-sha256", metavar="HEX", help="SHA-256 of the sample's original")
            r.add_argument("--expected-marker", metavar="8HEX", help="session marker for decrypt_copy.py")
            r.add_argument("--decrypt-from", metavar="NAS_FOLDER", help="decrypt copies of every *.L0CK3D below it")
            r.add_argument("--decrypt-to", metavar="DIR", help="local / external folder for decrypted copies")
            r.add_argument("--keep-copies", action="store_true", help="keep the downloaded ciphertext copies")
            r.add_argument("--python", metavar="PATH", help="Python >= incident.rescue_min_python for the toolkit")
            r.add_argument("--force-same-volume", action="store_true",
                           help="capture onto the volume that holds the encrypted data")
            r.add_argument("--force-unverified-key", action="store_true",
                           help="decrypt with the first key candidate when no --sample verified one")
            r.add_argument("--force-unpinned-toolkit", action="store_true",
                           help="--rescue-dir at another commit or with local changes; requirements without known "
                                "hashes installed without hash checks")
            g = sp.add_argument_group("incident fix")
            g.add_argument("--dry-run", action="store_true", help="print the plan and the API calls; send no write")
            g.add_argument("--yes", action="store_true", help="apply without asking")
            g.add_argument("--only", metavar="FIX,...", help="only these fixes (" + ", ".join(incident.FIX_ORDER) + ")")
            g.add_argument("--skip", metavar="FIX,...", help="leave these fixes out")
            g.add_argument("--share", action="append", help="limit snapshot fixes to this share (repeatable)")
            g.add_argument("--upgrade", action="store_true", help="also install the newest DSM build (reboots)")
            g.add_argument("--rotate-password", action="store_true",
                           help="also change this account's password to a random one and store it (1Password/keychain)")
            g.add_argument("--ransom-scan", action="store_true", help="also run the ransom-note scan (same as --scan)")
            g.add_argument("--force-firewall", action="store_true",
                           help="apply the firewall change even when the lockout check does not pass")
            g.add_argument("--force-admin", action="store_true",
                           help="disable admin even when it is the signed-in or only enabled administrator")
            g.add_argument("--i-know-snapshots-may-rotate", action="store_true",
                           help="allow the snapshot fixes without a clean --ransom-scan (starting snapshots applies "
                                "retention, which can delete older snapshots)")
        if name == "login":
            sp.add_argument("--save", action="store_true",
                            help="store the password in the macOS Keychain / Linux Secret Service for later runs")
            sp.add_argument("--trust-device", action="store_true",
                            help="on a 2FA login, ask DSM for a trusted-device token so later logins skip the code")
            sp.add_argument("--no-cache", action="store_true", help="just test the login; do not cache the session")
        if name == "logout":
            sp.add_argument("--forget", action="store_true",
                            help="also delete the keychain entry and the trusted-device token")
        if name == "setup":
            sp.add_argument("--origin", dest="setup_origin", action="append", metavar="URL",
                            help="DSM address, e.g. https://192.168.0.10:5001 (repeatable; LAN first, then VPN)")
            sp.add_argument("--user", help="DSM account (an administrator)")
            sp.add_argument("--password-source", metavar="SOURCE",
                            help="op:op://VAULT/ITEM/FIELD | command:CMD | keychain | env | prompt")
            sp.add_argument("--otp-source", metavar="SOURCE", help="op | command:CMD | prompt | none")
            sp.add_argument("--otp-code", metavar="CODE", help="current 2-step code for this one login")
            sp.add_argument("--trust-device", action="store_true",
                            help="ask DSM for a trusted-device token so later logins need no code")
            sp.add_argument("--save-to-keychain", action="store_true",
                            help="store the password in the OS keychain (from --password-stdin or a prompt)")
            sp.add_argument("--password-stdin", action="store_true", help="read the password from one stdin line")
            sp.add_argument("--tls", choices=["pin", "verify"], help="pin (default): trust on first use; verify: system CAs")
            sp.add_argument("--allowed-network", action="append", metavar="CIDR",
                            help="network allowed by incident fix's firewall/AutoBlock, e.g. 192.168.0.0/24 (repeatable)")
            sp.add_argument("--stage-dir", metavar="PATH",
                            help="folder in a writable shared folder for incident --deep and alert-deploy, "
                                 "e.g. /SHARE/.nas-cli-deploy")
            sp.add_argument("--webhook-file", metavar="PATH", help='JSON {"url", "header"} for alert --push / alert-deploy')
            sp.add_argument("--config", metavar="PATH", help="config file to write (default: NAS_CONFIG or "
                                                             "~/.config/synology-nas-cli/config.json)")
        if name == "mcp":
            sp.add_argument("--files-only", action="store_true", help="expose only allowlisted file list/download tools")
            sp.add_argument("--auto-confirm", action="store_true",
                            help="incident_fix applies the plan when a call has no confirm argument "
                                 "(confirm: false stays a dry run; NAS_YES and assume_yes do not apply to MCP)")
        if name == "trust":
            sp.add_argument("--reset", metavar="ORIGIN",
                            help="forget the certificate trusted for ORIGIN (e.g. https://192.0.2.10:5001); "
                                 "the next connection trusts whatever it presents")
        if name == "config":
            sp.add_argument("action", choices=["init", "show"])
            sp.add_argument("--force", action="store_true", help="init: overwrite an existing file")
        if name == "file":
            sp.add_argument("action", choices=["list", "download"])
            sp.add_argument("path", metavar="NAS_PATH")
            sp.add_argument("--offset", type=int, default=0)
            sp.add_argument("--limit", type=int, default=100)
        if name == "api":
            sp.add_argument("api_name", metavar="NAME", help="e.g. SYNO.Core.System")
            sp.add_argument("method", metavar="METHOD", help="e.g. info")
            sp.add_argument("params", nargs="*", metavar="k=v")
            sp.add_argument("--version", type=int, dest="version", help="API version (default: highest that works)")
            sp.add_argument("--allow-write", action="store_true", help="permit non-read methods")
    return p


GLOBAL_FLAGS = ("--json", "--no-input", "--yes", "--force")


def assume_yes(flag: bool = False) -> bool:
    return bool(flag or os.environ.get("NAS_YES", "") not in ("", "0") or config.get().get("assume_yes"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # global switches work before or after the command
    found = {a for a in argv if a in GLOBAL_FLAGS}
    rest = [a for a in argv if a not in GLOBAL_FLAGS]
    # parse_known_args: `nas api X m --version 2 k=v` leaves k=v after an
    # option unparsed; fold those back into params instead of erroring.
    args, extra = parser.parse_known_args(rest)
    if extra:
        if args.cmd == "api" and all("=" in x and not x.startswith("-") for x in extra):
            args.params += extra
        else:
            parser.error("unrecognized arguments: " + " ".join(extra))
    args.json = args.json or "--json" in found
    args.no_input = args.no_input or "--no-input" in found
    args.assume_yes = assume_yes(args.global_yes or "--yes" in found)
    if args.assume_yes:
        args.yes = True
    elif not hasattr(args, "yes"):
        args.yes = False
    args.force = bool(getattr(args, "force", False) or args.global_force or "--force" in found)
    return args


def config_cmd(args):
    if args.action == "show":
        cfg = config.masked()
        src = Credentials(config.get()).describe()
        data = {"_file": config.loaded_from(), "_env": config.env_used(), "_credential_source": src, **cfg}
        return [json.dumps(data, ensure_ascii=False, indent=2)], data
    path, _ = config.config_path()
    if os.path.exists(path) and not args.force:
        raise NasError(f"{path} exists (use --force to overwrite)")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config.EXAMPLE, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return [f"wrote {path}", "Edit origins and credentials; every key is described in README.md#configuration."], \
        {"path": path}


def trust_cmd(args):
    from .backends import load_pins, origin_key, save_pins
    tls = config.get()["tls"]
    path = config.path(tls["known_certs_file"])
    pins = load_pins(path)
    if args.reset:
        key = origin_key(args.reset)
        if key not in pins:
            raise NasError(f"{key} is not in {path}")
        del pins[key]
        save_pins(path, pins)
        return [f"forgot the certificate of {key}; the next connection trusts the one it presents"], {"removed": key}
    lines = [f"{k}  sha256 {v.get('sha256')}  (first seen {v.get('first_seen')})" for k, v in sorted(pins.items())]
    if tls["verify"]:
        lines.insert(0, "tls.verify is true: certificates are checked against the system CAs, not pinned")
    return lines or [f"no certificates trusted yet ({path})"], {"file": path, "pins": pins}


def login_cmd(args, lan):
    b = PasswordBackend(lan if lan is not None else config.get()["origins"], use_cache=False)
    if args.trust_device:
        b.trust_device = True
    b.login(save=not args.no_cache)
    lines = [f"Logged in as {b.account} via {b.origin} (credentials: {b.creds.describe().get('source')})"]
    data = {"account": b.account, "origin": b.origin, "session_file": None, "stored": None}
    if args.no_cache:
        b.logout()
    else:
        data["session_file"] = b._cache_path()
        lines.append(f"Session cached in {data['session_file']} (mode 600); `nas logout` ends it")
    if args.save:
        data["stored"] = b.creds.store_write(b.account, b.creds.password(b.account))
        lines.append(f"Password stored in {data['stored']} (service {b.creds.cfg.get('store_service')!r})")
    return lines, data


def logout_cmd(args, lan):
    b = PasswordBackend(lan if lan is not None else config.get()["origins"])
    lines, data = [], {"session": False, "keychain": False, "device_token": False}
    if b.session_kind == "cache":
        try:
            b.logout(force=True)
        except NasError as e:
            lines.append(f"DSM logout failed ({e}); removing the cache anyway")
        data["session"] = b.drop_session()
        lines.append("Cached session ended and removed")
    elif b.drop_session():
        data["session"] = True
        lines.append("Removed a cached session for an origin that is not reachable now")
    else:
        lines.append("No cached session")
    if args.forget:
        data["keychain"] = b.creds.store_delete(b.creds.cfg.get("username") or None)
        data["device_token"] = b.forget_device()
        lines.append(f"Keychain entry {'removed' if data['keychain'] else 'not found'}; "
                     f"trusted-device token {'removed' if data['device_token'] else 'not found'}")
    return lines, data


_COLORS = (("1;31", "FAIL|CRITICAL"), ("33", "WARN|WARNING|REFUSED"), ("32", "PASS|OK"), ("2", "SKIP"))
_STATUS = re.compile(r"\b(" + "|".join(p for _, p in _COLORS) + r")\b")


def _paint(text: str) -> str:
    """Status words in color, suggested commands in cyan, when stdout is a terminal
    (pipes, NO_COLOR and TERM=dumb stay plain)."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb" or not sys.stdout.isatty():
        return text

    def color(m):
        code = next(c for c, p in _COLORS if re.fullmatch(p, m.group(1)))
        return f"\033[{code}m{m.group(1)}\033[0m"

    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("-> "):
            out.append(f"\033[36m{line}\033[0m")
        else:
            out.append(_STATUS.sub(color, line).replace("(changed)", "\033[1m(changed)\033[0m"))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    config_error = None
    try:
        config.load()
    except config.ConfigError as e:
        words = sys.argv[1:] if argv is None else argv
        if "doctor" not in words and "setup" not in words:
            print(f"nas: {e}", file=sys.stderr)
            return 2
        config_error = str(e)
        config.load_defaults()
    args = parse_args(argv)
    if args.no_input:
        set_no_input(True)
    lan = ([o.strip().rstrip("/") for x in args.lan_origin for o in x.split(",") if o.strip()]
           if args.lan_origin else None)
    origins = [o.rstrip("/") for o in args.origin] if args.origin else None
    if args.op_item:
        config.get()["credentials"]["op_username"] = args.op_item.rstrip("/") + "/username"
        config.get()["credentials"]["op_password"] = args.op_item.rstrip("/") + "/password"
    if args.cmd == "mcp":
        from .mcp import serve
        return serve(sys.stdin, sys.stdout, lambda: open_session(args.backend, origins, lan),
                     auto_confirm=args.auto_confirm, lan_origins=lan, **({'files_only': True} if args.files_only else {}))
    if args.cmd in NO_SESSION:
        try:
            if args.cmd == "config":
                lines, data = config_cmd(args)
            elif args.cmd == "trust":
                lines, data = trust_cmd(args)
            elif args.cmd in ("setup", "doctor"):
                if args.cmd == "setup":
                    args.origin = args.setup_origin
                    lines, data, rc = onboard.setup(args)
                else:
                    lines, data, rc = onboard.doctor(args, config_error)
                print(json.dumps(data, ensure_ascii=False, indent=2, default=str) if args.json else _paint("\n".join(lines)))
                return rc
            elif args.cmd == "login":
                lines, data = login_cmd(args, lan)
            else:
                lines, data = logout_cmd(args, lan)
        except config.ConfigError as e:
            print(f"nas: {e}", file=sys.stderr)
            return 2
        except NasError as e:
            print(f"nas: {e}", file=sys.stderr)
            return e.exit_code
        print(json.dumps(data, ensure_ascii=False, indent=2) if args.json else _paint("\n".join(lines)))
        return 0
    fn = (files.file_list if args.action == "list" else files.file_download) if args.cmd == "file" else COMMANDS[args.cmd][0]
    pushing = args.cmd == "alert" and bool(args.push)
    if pushing:
        # one run at a time: the scheduler can start a run while a slow one is still going
        os.makedirs(os.path.dirname(os.path.abspath(args.state)), exist_ok=True)
        lock = open(os.path.join(os.path.dirname(os.path.abspath(args.state)), ".lock"), "w")
        try:
            import fcntl  # not on Windows; there runs are not serialised
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            pass
        except OSError:
            print("nas: another `alert --push` run is still going; skipped", file=sys.stderr)
            return 0
    session = None
    try:
        session = open_session(args.backend, origins, lan)
        result = fn(session, args)
        lines, data = result[0], result[1]
        rc = result[2] if len(result) > 2 else 0
    except Exception as e:
        if not (isinstance(e, NasError) or pushing):
            raise
        if isinstance(e, NasError):
            print(f"nas: {e}", file=sys.stderr)
        else:  # unexpected crash under the scheduler: still report it through the webhook
            traceback.print_exc()
        if pushing:
            try:
                print(alert.push_failure(args, str(e) if isinstance(e, NasError) else f"{type(e).__name__}: {e}"),
                      file=sys.stderr)
            except Exception as e2:
                print(f"nas: push_failure: {e2}", file=sys.stderr)
        return e.exit_code if isinstance(e, NasError) else 1
    except KeyboardInterrupt:
        return 130
    finally:
        if session is not None:
            try:
                session.close()
            except NasError:
                pass
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    else:
        print(_paint("\n".join(lines)))
    return rc
