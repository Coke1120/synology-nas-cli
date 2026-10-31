"""DSM Web API transports.

Every backend exposes `call_many(calls)` where each call is a dict
{api, method, params, version}. A result is {ok, data | error, version}.
When `version` is None the highest version is tried first and lower ones
are tried on "method/version not supported" (103/104).

Secrets (SynoToken, SID, passwords) never leave this module: they are not
returned, printed, or written anywhere.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config
from .credentials import Credentials
from .errors import AuthFailed, Blocked, CertificateChanged, NasError, Unreachable

__all__ = ["NasError", "describe_error", "open_session", "Session", "PasswordBackend", "ChromeBackend",
           "LocalBackend"]


COMMON_ERRORS = {
    100: "unknown error",
    101: "missing api/method/version parameter",
    102: "API does not exist",
    103: "method does not exist (try another --version)",
    104: "version not supported (try another --version)",
    105: "insufficient privilege",
    106: "session timeout",
    107: "session interrupted by duplicate login",
    109: "network unstable or system busy",
    114: "missing required parameters",
    117: "file system error",
    119: "SID not found (session expired, log in again)",
    120: "invalid parameter",
    150: "request source IP does not match login IP",
}

AUTH_ERRORS = {
    400: "no such account or incorrect password",
    401: "account disabled",
    402: "permission denied",
    403: "2-step verification code required",
    404: "2-step verification failed",
    406: "2-step verification enforced",
    407: "IP blocked by auto block",
    408: "expired password, cannot change",
    409: "expired password",
    410: "password must be changed",
    498: "DSM is upgrading, retry later",
    499: "system not ready (e.g. post-upgrade tasks still running), retry later",
}

FILESTATION_ERRORS = {
    400: "invalid parameter of file operation",
    401: "unknown error of file operation",
    402: "system too busy",
    403: "user not allowed this file operation",
    407: "operation not permitted",
    408: "no such file or directory",
    411: "read-only file system",
    599: "no such task of file operation",
}


def describe_error(api: str, result: dict) -> str:
    if result.get("noapi"):
        return f"{api} is not registered on this NAS"
    if "raw" in result:
        return f"HTTP {result.get('http')}: non-JSON response"
    err = result.get("error") or {}
    code = err.get("code")
    table = dict(COMMON_ERRORS)
    if api.startswith("SYNO.API.Auth"):
        table.update(AUTH_ERRORS)
    elif api.startswith("SYNO.FileStation"):
        table.update(FILESTATION_ERRORS)
    text = table.get(code, "see DSM API error codes")
    return f"code {code}: {text} (v{result.get('version')})"


def _stringify(params: dict | None) -> dict[str, str]:
    out = {}
    for k, v in (params or {}).items():
        out[k] = v if isinstance(v, str) else json.dumps(v)
    return out


def _encode_params(params: dict | None, json_format: bool) -> dict[str, str]:
    """Form fields for one call.

    APIs whose SYNO.API.Info entry says requestFormat "JSON" (almost all of
    them on DSM 7.4) JSON-decode every field. A bare string such as
    id=Tailscale is not valid JSON; some APIs then fall back to the raw text,
    others report success and do nothing (Package.Uninstallation) or return
    120. So strings that are not already JSON get quoted; values that already
    parse (numbers, true/false, lists, "quoted") are sent as given.
    """
    out = _stringify(params)
    if json_format:
        for k, v in out.items():
            try:
                json.loads(v)
            except ValueError:
                out[k] = json.dumps(v)
    return out


# --- chrome ---------------------------------------------------------------

# Runs in Chrome's isolated world for the DSM tab: no access to the page's
# SYNO globals, and DSM's CSP blocks injected inline scripts. The page's
# HttpOnly session cookie still rides on same-origin XHR, and the legacy
# login.cgi hands back the SynoToken for that session.
_JS_TEMPLATE = r"""
(function(){
try{
  var calls = __CALLS__;
  function req(m, url, body, tok){
    var x = new XMLHttpRequest(); x.open(m, url, false);
    if (body !== null) x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    if (tok) x.setRequestHeader('X-SYNO-TOKEN', tok);
    x.send(body); return x;
  }
  var tok = '';
  try { tok = JSON.parse(req('GET', '/webman/login.cgi?enable_syno_token=yes', null, null).responseText).SynoToken || ''; } catch(e) {}
  if (!tok) return JSON.stringify({fatal: 'not_logged_in'});
  var info = JSON.parse(req('GET', '/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all', null, null).responseText).data;
  function one(c){
    var i = info[c.api]; if (!i) return {ok: false, noapi: true};
    var jf = i.requestFormat === 'JSON';  // see _encode_params in backends.py
    var vs = [];
    if (c.version) vs = [c.version]; else for (var v = i.maxVersion; v >= i.minVersion; v--) vs.push(v);
    var last = null;
    for (var k = 0; k < vs.length; k++) {
      var p = 'api=' + encodeURIComponent(c.api) + '&version=' + vs[k] + '&method=' + encodeURIComponent(c.method);
      for (var key in c.params) {
        var val = c.params[key];
        if (jf) { try { JSON.parse(val); } catch(e) { val = JSON.stringify(val); } }
        p += '&' + encodeURIComponent(key) + '=' + encodeURIComponent(val);
      }
      var x = req('POST', '/webapi/' + i.path, p, tok), r;
      try { r = JSON.parse(x.responseText); } catch(e) { return {ok: false, http: x.status, raw: true, version: vs[k]}; }
      if (r.success) return {ok: true, data: (r.data === undefined ? null : r.data), version: vs[k]};
      last = {ok: false, error: r.error, version: vs[k]};
      var code = r.error && r.error.code;
      if (c.version || !(code === 103 || code === 104)) break;
    }
    return last;
  }
  return JSON.stringify({results: calls.map(one)});
} catch(e) { return JSON.stringify({fatal: 'js_error: ' + e}); }
})()
"""

_APPLESCRIPT = r"""
on run argv
  set js to item 1 of argv
  set origins to paragraphs of (item 2 of argv)
  if application "Google Chrome" is not running then return "NO_CHROME"
  tell application "Google Chrome"
    repeat with w in windows
      repeat with t in tabs of w
        set u to URL of t
        repeat with o in origins
          if (u is (o as text)) or (u starts with ((o as text) & "/")) then
            return execute t javascript js
          end if
        end repeat
      end repeat
    end repeat
  end tell
  return "NO_TAB"
end run
"""


class ChromeBackend:
    name = "chrome"

    def __init__(self, origins: list[str]):
        if sys.platform != "darwin":
            raise NasError("--backend chrome drives Google Chrome through AppleScript and only works on macOS")
        if not origins:
            raise NasError("no DSM origin for --backend chrome: set chrome_origins or origins in the config")
        self.origins = origins

    def describe(self) -> dict:
        return {"backend": self.name, "origins": self.origins}

    def call_many(self, calls: list[dict]) -> list[dict]:
        payload = [
            {"api": c["api"], "method": c["method"], "params": _stringify(c.get("params")),
             "version": c.get("version")}
            for c in calls
        ]
        js = _JS_TEMPLATE.replace("__CALLS__", json.dumps(payload))
        try:
            proc = subprocess.run(
                ["osascript", "-", js, "\n".join(self.origins)],
                input=_APPLESCRIPT, capture_output=True, text=True, timeout=180,
            )
        except subprocess.TimeoutExpired:
            raise NasError("Chrome did not answer within 180s")
        out = proc.stdout.strip()
        if proc.returncode != 0:
            msg = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "osascript failed"
            if "JavaScript" in msg and ("Apple" in msg or "turned off" in msg):
                msg += " — enable Chrome: View > Developer > Allow JavaScript from Apple Events"
            raise NasError(msg)
        if out == "NO_CHROME":
            raise NasError("Google Chrome is not running; open DSM in Chrome and log in")
        if out == "NO_TAB":
            raise NasError("no Chrome tab on " + " or ".join(self.origins) + "; open DSM there and log in")
        if out in ("", "missing value"):
            raise NasError("Chrome returned nothing (page still loading?)")
        doc = json.loads(out)
        if "fatal" in doc:
            if doc["fatal"] == "not_logged_in":
                raise NasError("the DSM tab is not logged in; log in to DSM in Chrome first")
            raise NasError(doc["fatal"])
        return doc["results"]


# --- password -------------------------------------------------------------

def _host_port(origin: str) -> tuple[str, int]:
    u = urllib.parse.urlsplit(origin)
    return u.hostname or "", u.port or (443 if u.scheme == "https" else 80)


# --- TLS: no proxies, and trust on first use for self-signed DSM certificates ---

class PinMismatch(CertificateChanged):
    pass


def origin_key(origin: str) -> str:
    host, port = _host_port(origin if "://" in origin else "https://" + origin)
    return f"https://[{host}]:{port}" if ":" in host else f"https://{host}:{port}"


def load_pins(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def save_pins(path: str, pins: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def check_pin(path: str, key: str, der: bytes) -> None:
    """Record the certificate on first use; refuse a different one later."""
    fp = hashlib.sha256(der or b"").hexdigest()
    pins = load_pins(path)
    known = (pins.get(key) or {}).get("sha256")
    if known is None:
        pins[key] = {"sha256": fp, "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")}
        save_pins(path, pins)
        print(f"nas: trusting the certificate of {key} on first use (sha256 {fp[:16]}...), stored in {path}",
              file=sys.stderr)
    elif known != fp:
        raise PinMismatch(
            f"the TLS certificate of {key} changed (trusted sha256 {known[:16]}..., now {fp[:16]}...). Someone may be "
            f"intercepting the connection. If you replaced the DSM certificate yourself: nas trust --reset {key}")


def make_opener(cfg: dict):
    """urllib opener for DSM: never uses HTTP(S)_PROXY or system proxies, verifies or pins the certificate."""
    tls = cfg.get("tls") or {}
    if tls.get("verify"):
        ctx, pins = ssl.create_default_context(), None
    else:
        ctx, pins = ssl._create_unverified_context(), config.path(tls.get("known_certs_file") or "")

    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            super().connect()
            if pins:
                try:
                    check_pin(pins, origin_key(f"https://{self.host}:{self.port}"),
                              self.sock.getpeercert(binary_form=True))
                except PinMismatch:
                    self.sock.close()
                    raise

    class Handler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(PinnedHTTPSConnection, req, context=ctx)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), Handler(context=ctx))


class PasswordBackend:
    """Direct HTTPS to DSM with an account from the credential chain (credentials.py).

    `origins` are tried in order (TCP connect with a short timeout) and the
    first reachable one is used, so one config works on the LAN and over a VPN.

    Sessions: by default every command logs in and logs out. After `nas login`
    the session (SID + SynoToken) is cached in session.cache_file (mode 600)
    and reused until DSM rejects it (106/107/119), then renewed. NAS_SID and
    NAS_SYNOTOKEN use a pasted DSM session instead (never logged out here).
    """

    name = "password"
    session_name = "nascli"
    RENEW_CODES = (106, 107, 119)

    def __init__(self, origins: list[str], creds: Credentials | None = None, cfg: dict | None = None,
                 use_cache: bool = True):
        self.cfg = cfg or config.get()
        self.origins = [o.rstrip("/") for o in origins if o]
        self.origin = None
        self.creds = creds or Credentials(self.cfg)
        self.account = None  # not secret; shown by `nas whoami`
        self.opener = make_opener(self.cfg)
        self._info = None
        self._sid = None
        self._token = None
        self._rejected = None  # (sha256 of account+password, error) of a login DSM refused
        self.session_kind = None  # "login" (this process), "cache" (nas login) or "env" (NAS_SID)
        self.trust_device = bool(self.cfg["session"].get("trust_device"))
        if use_cache:
            self._adopt_session()

    def describe(self) -> dict:
        d = {"backend": self.name, "origin": self.origin, "tried": self.origins,
             "session": self.session_kind or "per-command"}
        d.update({k: v for k, v in self.creds.describe().items() if k in ("source", "op_ref", "store", "command")})
        return d

    # --- session cache ------------------------------------------------------

    def _cache_path(self) -> str:
        return config.path(self.cfg["session"].get("cache_file") or "")

    def _adopt_session(self) -> None:
        sid = os.environ.get("NAS_SID")
        if sid:
            self._sid, self._token, self.session_kind = sid, os.environ.get("NAS_SYNOTOKEN") or None, "env"
            return
        path = self._cache_path()
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        origin = (d.get("origin") or "").rstrip("/")
        if not d.get("sid") or (self.origins and origin not in self.origins):
            return
        host, port = _host_port(origin)
        try:
            socket.create_connection((host, port), timeout=self.cfg.get("connect_timeout", 3.0)).close()
        except OSError:
            return  # cached origin not reachable from here: log in normally
        self.origin, self._sid, self._token = origin, d["sid"], d.get("synotoken")
        self.account, self.session_kind = d.get("account"), "cache"

    def save_session(self) -> str:
        path = self._cache_path()
        if not path:
            raise NasError("session.cache_file is empty in the config")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"origin": self.origin, "account": self.account, "sid": self._sid,
                       "synotoken": self._token, "created": time.strftime("%Y-%m-%d %H:%M:%S")}, f)
        os.chmod(path + ".tmp", 0o600)
        os.replace(path + ".tmp", path)
        self.session_kind = "cache"
        return path

    def drop_session(self) -> bool:
        path = self._cache_path()
        if path and os.path.isfile(path):
            os.remove(path)
            return True
        return False

    # --- trusted device (2FA) -------------------------------------------------

    def _device_path(self) -> str:
        return config.path(self.cfg["session"].get("device_token_file") or "")

    def _device_id(self, account: str) -> str | None:
        path = self._device_path()
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return None
        return (d.get("devices") or {}).get(account)

    def _save_device_id(self, account: str, did: str) -> None:
        path = self._device_path()
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        d.setdefault("devices", {})[account] = did
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.chmod(path + ".tmp", 0o600)
        os.replace(path + ".tmp", path)

    def forget_device(self) -> bool:
        path = self._device_path()
        if path and os.path.isfile(path):
            os.remove(path)
            return True
        return False

    # --- origins and 1Password helpers kept for callers ----------------------

    def select_origin(self) -> str:
        if self.origin:
            return self.origin
        if not self.origins:
            raise NasError("no DSM origin configured: run nas setup --origin https://NAS:5001 (or set \"origins\" "
                           "in the config, NAS_ORIGINS, or --lan-origin)")
        errors = []
        for o in self.origins:
            host, port = _host_port(o)
            try:
                socket.create_connection((host, port), timeout=self.cfg.get("connect_timeout", 3.0)).close()
            except OSError as e:
                errors.append(f"{o}: {type(e).__name__}")
                continue
            self.origin = o
            return o
        raise Unreachable("no DSM origin reachable (" + "; ".join(errors) + "). "
                       "Set NAS_ORIGINS (comma-separated), --lan-origin, or origins in the config.")

    def op_item_json(self, ref: str) -> dict:
        """Whole 1Password item (op://VAULT/ITEM) as JSON. Callers must not print secret fields."""
        from .credentials import parse_op_item
        vault, item = parse_op_item(ref)
        return self.creds.op_item_json(vault, item)

    def confirm_password(self) -> str:
        """SynoConfirmPWToken, which DSM wants before it saves a root-owned scheduled task."""
        if not self._sid:
            self.login()
        passwd = self.creds.password(self.account)
        r = self.call_many([{"api": "SYNO.Core.User.PasswordConfirm", "method": "auth", "version": 2,
                             "params": {"password": passwd}}])[0]
        del passwd
        tok = (r.get("data") or {}).get("SynoConfirmPWToken") if r.get("ok") else None
        if not tok:
            raise NasError("SYNO.Core.User.PasswordConfirm: " + describe_error("SYNO.Core.User.PasswordConfirm", r))
        return tok

    def _url(self, path: str, auth: bool = True) -> str:
        url = self.select_origin() + path
        if auth and self._token:
            # This DSM ignores the X-SYNO-TOKEN header and the form field for
            # API calls (error 119); only the query parameter is accepted.
            url += ("&" if "?" in url else "?") + "SynoToken=" + urllib.parse.quote(self._token)
        return url

    def _open(self, req: urllib.request.Request, timeout: float):
        try:
            return self.opener.open(req, timeout=timeout)
        except urllib.error.URLError as e:
            if isinstance(e.reason, NasError):
                raise e.reason
            raise

    def _send(self, req: urllib.request.Request, timeout: float) -> dict:
        try:
            with self._open(req, timeout) as r:
                body = r.read().decode("utf-8", "replace")
        except NasError:
            raise
        except Exception as e:  # never echo the request body
            raise NasError(f"HTTP to {self.origin} failed: {type(e).__name__}: {getattr(e, 'reason', e)}")
        try:
            return json.loads(body)
        except ValueError:
            return {"success": False, "raw": True}

    def _http(self, path: str, fields: dict[str, str] | None = None, timeout: float = 60) -> dict:
        data = urllib.parse.urlencode(fields).encode() if fields is not None else None
        return self._send(urllib.request.Request(self._url(path), data=data), timeout)

    def get_text(self, path: str, timeout: float = 10) -> str:
        """Unauthenticated GET, e.g. SessionData while DSM is rebooting."""
        req = urllib.request.Request(self._url(path, auth=False))
        with self._open(req, timeout) as r:
            return r.read().decode("utf-8", "replace")

    def _api_info(self) -> dict:
        if self._info is None:
            r = self._http("/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all")
            if not r.get("success"):
                raise NasError("SYNO.API.Info query failed")
            self._info = r["data"]
        return self._info

    def login(self, save: bool = False) -> None:
        """Log in with the credential chain. Never retried with the same password:
        each failure counts toward AutoBlock, so the same account and password are not sent again
        in this process after DSM refused them (a changed password is tried)."""
        self.select_origin()
        info = self._api_info()["SYNO.API.Auth"]
        version = min(6, info["maxVersion"])
        account = self.creds.username()
        passwd = self.creds.password(account)
        tried = hashlib.sha256(f"{account}\0{passwd}".encode()).hexdigest()
        if self._rejected and self._rejected[0] == tried:
            raise self._rejected[1]
        fields = {
            "api": "SYNO.API.Auth", "version": str(version), "method": "login",
            "account": account, "passwd": passwd, "session": self.session_name,
            "format": "sid", "enable_syno_token": "yes",
        }
        did = self._device_id(account)
        if did:
            fields.update(device_id=did, device_name=self.cfg["session"].get("device_name") or "synology-nas-cli")
        r = self._http("/webapi/" + info["path"], fields)
        if not r.get("success") and (r.get("error") or {}).get("code") == 403:
            # 2-step verification: one more try with a current code (a code is not a password guess)
            otp = self.creds.otp()
            if otp:
                f2 = {**fields, "otp_code": otp}
                if self.trust_device:
                    f2.update(enable_device_token="yes",
                              device_name=self.cfg["session"].get("device_name") or "synology-nas-cli")
                r = self._http("/webapi/" + info["path"], f2)
                if r.get("success") and self.trust_device and (r.get("data") or {}).get("did"):
                    self._save_device_id(account, r["data"]["did"])
        del passwd, fields
        if not r.get("success"):
            code = (r.get("error") or {}).get("code")
            hint = LOGIN_HINTS.get(code, "")
            cls = Blocked if code == 407 else Unreachable if code in (498, 499) else AuthFailed
            exc = cls("DSM login failed: "
                      + describe_error("SYNO.API.Auth", {"error": r.get("error"), "version": version})
                      + (f"\n{hint}" if hint else ""))
            exc.code = code  # DSM's login error code (400, 403, 407, ...)
            if code not in (407, 498, 499):  # blocked or upgrading: not a verdict on the password
                self._rejected = (tried, exc)
            raise exc
        self._rejected = None
        self.account = account
        self._sid = r["data"]["sid"]
        self._token = r["data"].get("synotoken")
        self.session_kind = "login"
        if save:
            self.save_session()

    def logout(self, force: bool = False) -> None:
        """End a session this process opened. Cached (`nas login`) and pasted (NAS_SID)
        sessions stay open unless force=True (`nas logout`)."""
        if not self._sid or (self.session_kind in ("cache", "env") and not force):
            return
        info = self._api_info()["SYNO.API.Auth"]
        try:
            self._http("/webapi/" + info["path"], {
                "api": "SYNO.API.Auth", "version": "1", "method": "logout",
                "session": self.session_name, "_sid": self._sid,
            })
        finally:
            self._sid = None
            self._token = None

    def _renew(self, code) -> None:
        if self.session_kind == "env":
            raise NasError(f"the DSM session in NAS_SID was rejected (code {code}); paste a fresh one or unset NAS_SID")
        self._sid = self._token = None
        self.login(save=self.session_kind == "cache")

    def call_many(self, calls: list[dict]) -> list[dict]:
        if not self._sid:
            self.login()
        info = self._api_info()
        results = []
        for c in calls:
            i = info.get(c["api"])
            if not i:
                results.append({"ok": False, "noapi": True})
                continue
            versions = [c["version"]] if c.get("version") else list(range(i["maxVersion"], i["minVersion"] - 1, -1))
            last = None
            renewed = False
            k = 0
            while k < len(versions):
                v = versions[k]
                fields = {"api": c["api"], "version": str(v), "method": c["method"], "_sid": self._sid}
                fields.update(_encode_params(c.get("params"), i.get("requestFormat") == "JSON"))
                r = self._http("/webapi/" + i["path"], fields, timeout=c.get("timeout", 60))
                if r.get("raw"):
                    last = {"ok": False, "raw": True, "version": v}
                    break
                if r.get("success"):
                    last = {"ok": True, "data": r.get("data"), "version": v}
                    break
                last = {"ok": False, "error": r.get("error"), "version": v}
                code = (r.get("error") or {}).get("code")
                # DSM drops sessions now and then (119 right after a good login); one new login, once
                if code in self.RENEW_CODES and not renewed and self.session_kind in ("cache", "env", "login"):
                    self._renew(code)
                    renewed = True
                    continue  # same version again with the new session
                if c.get("version") or code not in (103, 104):
                    break
                k += 1
            results.append(last)
        return results

    def upload(self, api: str, method: str, version: int, fields: dict[str, str], path: str,
               timeout: float = 3600) -> dict:
        """multipart/form-data POST of one file, streamed from disk.

        DSM reads the form fields before `file`, so they go first.
        """
        if not self._sid:
            self.login()
        info = self._api_info().get(api)
        if not info:
            return {"ok": False, "noapi": True}
        boundary = "----nascli" + os.urandom(12).hex()
        head = b"".join(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
            for k, v in {"api": api, "method": method, "version": str(version), **fields}.items()
        ) + (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
             f'filename="{os.path.basename(path)}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        size = os.path.getsize(path)

        def body():
            yield head
            with open(path, "rb") as f:
                while chunk := f.read(1 << 20):
                    yield chunk
            yield tail

        q = urllib.parse.urlencode({"api": api, "method": method, "version": str(version), "_sid": self._sid})
        req = urllib.request.Request(self._url(f"/webapi/{info['path']}?{q}"), data=body(), headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(head) + size + len(tail)),
        })
        r = self._send(req, timeout)
        if r.get("raw"):
            return {"ok": False, "raw": True, "version": version}
        if r.get("success"):
            return {"ok": True, "data": r.get("data"), "version": version}
        return {"ok": False, "error": r.get("error"), "version": version}


    def download_to(self, fs_path: str, local_path: str, timeout: float = 600, max_bytes: int = None) -> int:
        """Stream one File Station file (e.g. /share/dir/file) to a new local file (mode 600). Returns bytes."""
        if not self._sid:
            self.login()
        origin = self.select_origin()
        q = urllib.parse.urlencode({"api": "SYNO.FileStation.Download", "version": "2", "method": "download",
                                    "mode": "download", "path": json.dumps([fs_path])})
        req = urllib.request.Request(self._url("/webapi/entry.cgi?" + q))
        req.add_header("Cookie", f"id={self._sid}")
        req.add_header("Origin", origin)
        n = 0
        created = False
        try:
            with self._open(req, timeout) as r:
                ctype = r.headers.get("Content-Type", "")
                first = r.read(1 << 20)
                if ctype.startswith("application/json") and first.lstrip().startswith(b'{"error"'):
                    raise NasError(f"download {fs_path}: {first[:200].decode('utf-8', 'replace')}")
                fd = os.open(local_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created = True
                try:
                    out = os.fdopen(fd, "wb")
                except BaseException:
                    os.close(fd)
                    raise
                # The cleanup scope includes buffered flush/close and response close.
                with out:
                    block = first
                    while block:
                        if max_bytes is not None and n + len(block) > max_bytes:
                            raise NasError("download exceeds NAS_FILE_MAX_BYTES")
                        out.write(block)
                        n += len(block)
                        block = r.read(1 << 20)
        except BaseException as exc:
            if created:
                try:
                    os.unlink(local_path)
                except FileNotFoundError:
                    pass
                except OSError:
                    raise NasError("download failed; could not remove partial local file") from exc
            if isinstance(exc, FileExistsError):
                raise NasError("download destination already exists; refusing to overwrite") from exc
            if isinstance(exc, (OSError, http.client.HTTPException)):
                # Transport exception text may contain a URL or session details.
                raise NasError(f"download failed ({type(exc).__name__})") from exc
            raise
        return n

    def http_raw(self, path: str, data: bytes | None = None, headers: dict | None = None,
                 cookies: dict | None = None, timeout: float = 30) -> tuple[int, dict, str, dict]:
        """Request a DSM-hosted page with the session cookie (`id=<sid>`).

        Returns (status, headers, body, cookies set by the response). A DSM error answer 106/107/119
        (session dropped) is followed by one new login and the same request once more, as in call_many.
        """
        if not self._sid:
            self.login()
        out = self._http_raw_once(path, data, headers, cookies, timeout)
        code = _dsm_error_code(out[2])
        if code in self.RENEW_CODES and self.session_kind in ("cache", "env", "login"):
            self._renew(code)
            out = self._http_raw_once(path, data, headers, cookies, timeout)
        return out

    def _http_raw_once(self, path, data, headers, cookies, timeout) -> tuple[int, dict, str, dict]:
        origin = self.select_origin()
        req = urllib.request.Request(origin + path, data=data, method="POST" if data is not None else "GET")
        jar = {"id": self._sid, **(cookies or {})}
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))
        req.add_header("X-Syno-Token", self._token or "")
        req.add_header("Origin", origin)
        req.add_header("Referer", origin + "/")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            resp = self._open(req, timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except (TimeoutError, socket.timeout):
            raise NasError(f"{path}: no answer within {timeout:.0f}s")
        except urllib.error.URLError as e:
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                raise NasError(f"{path}: no answer within {timeout:.0f}s")
            raise NasError(f"HTTP to {origin} failed: {e.reason}")
        try:
            body = resp.read().decode("utf-8", "replace")
        except (TimeoutError, socket.timeout):
            raise NasError(f"{path}: no answer within {timeout:.0f}s")
        set_cookies = {}
        for c in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = c.partition("=")
            set_cookies[name.strip()] = rest.split(";", 1)[0]
        return resp.status if hasattr(resp, "status") else resp.code, dict(resp.headers), body, set_cookies


def _dsm_error_code(body: str):
    """The code of a DSM Web API error answer ({"error": {"code": N}, "success": false}), else None."""
    if not body.lstrip().startswith("{") or '"error"' not in body[:200]:
        return None
    try:
        d = json.loads(body)
    except ValueError:
        return None
    return (d.get("error") or {}).get("code") if isinstance(d, dict) and d.get("success") is False else None

LOGIN_HINTS = {
    400: "Check the username/password your credential source returns (`nas config show` names the source). "
         "Each failure counts toward AutoBlock (DSM default: 10 failures in 5 min blocks this IP).",
    403: "The account has 2-step verification on and no code was available: set credentials.otp_command, "
         "add the 2FA secret to the 1Password item as a one-time password, or run in a terminal to be prompted.",
    404: "DSM rejected the 2-step verification code. Check both clocks and the code source.",
    406: "DSM enforces 2-step verification for this account but it is not set up yet: sign in once in the "
         "browser and enroll, then configure a code source.",
    407: "This IP is blocked by AutoBlock. Unblock it in DSM from another address: Control Panel > Security > "
         "Protection > Allow/Block List > Block List (控制台 > 安全性 > 保護 > 允許/封鎖清單 > 封鎖清單).",
    498: "DSM is installing an update; wait until it reboots.",
    499: "DSM is not ready (typically right after an upgrade, while post-upgrade tasks run). Wait until "
         "SessionData reports dsm_upgrade_all_done = true (`nas upgrade --wait-only` polls it), then retry.",
}


class Session:
    """Thin wrapper so commands don't care which backend is in use."""

    def __init__(self, backend):
        self.backend = backend

    @property
    def backend_name(self) -> str:
        return self.backend.name

    def describe(self) -> dict:
        return self.backend.describe()

    def call_many(self, calls: list[dict]) -> list[dict]:
        return self.backend.call_many(calls)

    def call(self, api: str, method: str, params: dict | None = None, version: int | None = None,
             timeout: float | None = None) -> dict:
        c = {"api": api, "method": method, "params": params, "version": version}
        if timeout:
            c["timeout"] = timeout
        return self.call_many([c])[0]

    def http_raw(self, *a, **kw):
        if not hasattr(self.backend, "http_raw"):
            raise NasError(f"the {self.backend.name} backend cannot reach package web UIs; use --backend password")
        return self.backend.http_raw(*a, **kw)

    def download_to(self, *a, **kw) -> int:
        if not hasattr(self.backend, "download_to"):
            raise NasError("file download requires --backend password")
        return self.backend.download_to(*a, **kw)

    def upload(self, *a, **kw) -> dict:
        if not hasattr(self.backend, "upload"):
            raise NasError(f"the {self.backend.name} backend cannot upload files; use --backend password")
        return self.backend.upload(*a, **kw)

    def close(self) -> None:
        if hasattr(self.backend, "logout"):
            self.backend.logout()


# --- local -----------------------------------------------------------------

SYNOWEBAPI = "/usr/syno/bin/synowebapi"
TAILSCALE_BIN = "/var/packages/Tailscale/target/bin/tailscale"


class LocalBackend:
    """On the NAS itself, as root (DSM Task Scheduler): `synowebapi --exec`.

    No login and no password: synowebapi runs the API as SYSTEM_ADMIN. It
    prints a "[Line N] Exec WebAPI: ..." banner before the JSON, so the
    reply is parsed from the first "{".
    """

    name = "local"

    def __init__(self):
        if not os.access(SYNOWEBAPI, os.X_OK):
            raise NasError(f"{SYNOWEBAPI} not found: --backend local only works on the NAS, as root")
        self._info = None

    def describe(self) -> dict:
        return {"backend": self.name, "origin": "synowebapi"}

    def _exec(self, api: str, method: str, version: int, fields: dict[str, str], timeout: float) -> dict:
        argv = [SYNOWEBAPI, "--exec", f"api={api}", f"method={method}", f"version={version}"]
        argv += [f"{k}={v}" for k, v in fields.items()]
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": {"code": "timeout"}}
        out = p.stdout.decode("utf-8", "replace")
        start = out.find("{")
        try:
            return json.loads(out[start:]) if start >= 0 else {"raw": True}
        except ValueError:
            return {"raw": True}

    def _api_info(self) -> dict:
        if self._info is None:
            r = self._exec("SYNO.API.Info", "query", 1, {"query": '"all"'}, 60)
            if not r.get("success"):
                raise NasError(f"SYNO.API.Info via synowebapi failed: {r.get('error') or 'no JSON'}")
            self._info = r["data"]
        return self._info

    def call_many(self, calls: list[dict]) -> list[dict]:
        info = self._api_info()
        results = []
        for c in calls:
            i = info.get(c["api"])
            if not i:
                results.append({"ok": False, "noapi": True})
                continue
            versions = [c["version"]] if c.get("version") else list(range(i["maxVersion"], i["minVersion"] - 1, -1))
            last = None
            for v in versions:
                # synowebapi JSON-decodes every field, whatever requestFormat says
                r = self._exec(c["api"], c["method"], v, _encode_params(c.get("params"), True), c.get("timeout", 60))
                if r.get("raw"):
                    last = {"ok": False, "raw": True, "version": v}
                    break
                if r.get("success"):
                    last = {"ok": True, "data": r.get("data"), "version": v}
                    break
                last = {"ok": False, "error": r.get("error"), "version": v}
                code = (r.get("error") or {}).get("code")
                if c.get("version") or code not in (103, 104):
                    break
            results.append(last)
        return results

    def tailscale_data(self, timeout: float = 20) -> dict:
        """The fields `alert` reads from the Tailscale web UI's /api/data, from `tailscale status --json`."""
        try:
            p = subprocess.run([TAILSCALE_BIN, "status", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout)
            st = json.loads(p.stdout.decode("utf-8", "replace"))
        except (OSError, subprocess.TimeoutExpired, ValueError) as e:
            raise NasError(f"tailscale status --json: {e}")
        me = st.get("Self") or {}
        return {"Status": st.get("BackendState"), "KeyExpiry": me.get("KeyExpiry") or "",
                "KeyExpired": bool(me.get("Expired"))}


def open_session(name: str, chrome_origins: list[str] | None = None, lan_origins: list[str] | None = None,
                 creds: Credentials | None = None) -> Session:
    cfg = config.get()
    if name == "chrome":
        return Session(ChromeBackend(chrome_origins if chrome_origins is not None else cfg["chrome_origins"]))
    if name == "password":
        return Session(PasswordBackend(lan_origins if lan_origins is not None else cfg["origins"], creds, cfg))
    if name == "local":
        return Session(LocalBackend())
    raise NasError(f"unknown backend {name!r}")
