#!/usr/bin/env python3
"""Backend for the OpenConnect bar widget.

  helper.py list              JSON list of NetworkManager OpenConnect profiles
  helper.py connect <uuid>    Interactive login; JSON events on stdout,
                              JSON answers on stdin ({"answer": "..."} / {"cancel": true})
  helper.py disconnect <uuid>
  helper.py save              Create / update a profile from JSON on stdin
  helper.py delete <uuid>

Passwords are never written to disk by this helper: they live in the Secret
Service keyring (gnome-keyring) via secret-tool, travel over stdin only, and
are only auto-filled into the password prompt, never into MFA / SMS prompts.

Authentication runs `openconnect --authenticate` on a pty so every server
prompt (username, password, SMS / MFA challenge, group, certificate) is
surfaced to the UI. The resulting cookie is handed to NetworkManager via an
nmcli passwd-file, so the tunnel, routes and DNS stay NM-managed and no root
is needed.
"""

import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

# Omarchy convention: plugin data under $XDG_STATE_HOME/omarchy, not ~/.config/omarchy.
STATE_DIR = os.path.join(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
                         "omarchy", "plugins", "shota.openconnect")
STATE_FILE = os.path.join(STATE_DIR, "state.json")

NOISE = re.compile(
    r"^(POST|GET) https?://|^Connected to |^SSL negotiation|^Connected to HTTPS|^XML POST enabled|"
    r"^Got HTTP response|^Server certificate verify failed|^Got CONNECT response|^CSTP connected|"
    r"^Please enter your username and password\.?$|^To trust this server|^\s*--servercert |"
    r"^Certificate from VPN server|^Reason: |^Enter .* to accept|^SSO token|^Opening|^Using "
)


def emit(event, **data):
    data["event"] = event
    sys.stdout.write(json.dumps(data) + "\n")
    sys.stdout.flush()


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


def nmcli(*args, check=False):
    return subprocess.run(["nmcli", *args], capture_output=True, text=True, check=check)


HIP_WRAPPER = "/usr/lib/openconnect/hipreport.sh"
SSO_PROTOCOLS = ("anyconnect", "gp", "fortinet")
FORTINET_SSO_PORT = 8020   # FortiGate redirects the browser here (same as FortiClient)
SSO_TIMEOUT = 300
GPAUTH_OS = {"win": "Windows", "mac-intel": "Mac", "linux-64": "Linux", "linux": "Linux"}
KEYRING_SERVICE = "omarchy-openconnect"
PROTOCOLS = ("anyconnect", "gp", "nc", "pulse", "f5", "fortinet", "array")
NEW_PROFILE_DATA = {
    "authtype": "password", "autoconnect-flags": "0", "certsigs-flags": "0", "cookie-flags": "2",
    "disable_udp": "no", "enable_csd_trojan": "no", "gateway-flags": "2", "gwcert-flags": "2",
    "lasthost-flags": "0", "pem_passphrase_fsid": "no", "prevent_invalid_cert": "no",
    "resolve-flags": "2", "stoken_source": "disabled", "xmlconfig-flags": "0",
}


def keyring_attrs(uuid):
    return ["service", KEYRING_SERVICE, "uuid", uuid]


def keyring_get(uuid):
    res = subprocess.run(["secret-tool", "lookup", *keyring_attrs(uuid)], capture_output=True, text=True)
    return res.stdout if res.returncode == 0 and res.stdout else None


def keyring_set(uuid, name, password):
    res = subprocess.run(["secret-tool", "store", "--label", "OpenConnect VPN: %s" % name, *keyring_attrs(uuid)],
                         input=password, capture_output=True, text=True)
    return res.returncode == 0


def keyring_clear(uuid):
    subprocess.run(["secret-tool", "clear", *keyring_attrs(uuid)], capture_output=True)


def split_terse(line):
    # nmcli -t escapes ':' as '\:'
    return [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]


def vpn_data(uuid):
    out = nmcli("-g", "vpn.data", "connection", "show", uuid).stdout.strip()
    data = {}
    for item in re.split(r",\s*(?=[\w-]+\s*=)", out):
        if "=" in item:
            k, v = item.split("=", 1)
            # nmcli -g escapes ':' and '\\'; vpn.data itself escapes ','
            data[k.strip()] = re.sub(r"\\([:\\,])", r"\1", v.strip())
    return data


def cmd_list():
    res = nmcli("-t", "-f", "NAME,UUID,TYPE", "connection", "show")
    active = {}
    for line in nmcli("-t", "-f", "UUID,STATE", "connection", "show", "--active").stdout.splitlines():
        parts = split_terse(line)
        if len(parts) >= 2:
            active[parts[0]] = parts[1]
    state = load_state()
    conns = []
    for line in res.stdout.splitlines():
        parts = split_terse(line)
        if len(parts) < 3 or parts[2] != "vpn":
            continue
        name, uuid = parts[0], parts[1]
        if nmcli("-g", "vpn.service-type", "connection", "show", uuid).stdout.strip() != "org.freedesktop.NetworkManager.openconnect":
            continue
        data = vpn_data(uuid)
        conns.append({
            "name": name,
            "uuid": uuid,
            "gateway": data.get("gateway", ""),
            "protocol": data.get("protocol", "anyconnect"),
            "state": active.get(uuid, ""),
            "usergroup": data.get("usergroup", ""),
            "username": state.get(uuid, {}).get("username", ""),
            "rememberPassword": bool(state.get(uuid, {}).get("rememberPassword")),
            "sso": bool(state.get(uuid, {}).get("sso")),
            "hip": data.get("enable_csd_trojan") == "yes" and bool(data.get("csd_wrapper")),
            "reportedOs": data.get("reported_os", ""),
            "lastUsed": state.get(uuid, {}).get("lastUsed", 0),
            "splitTunnel": nmcli("-g", "ipv4.never-default", "connection", "show", uuid).stdout.strip() == "yes",
        })
    json.dump({"ok": res.returncode == 0, "error": res.stderr.strip(), "connections": conns}, sys.stdout)


def cmd_disconnect(uuid):
    res = nmcli("connection", "down", uuid)
    if res.returncode != 0:
        sys.stderr.write(res.stderr)
    sys.exit(res.returncode)


def format_vpn_data(data):
    return ", ".join("%s = %s" % (k, str(v).replace(",", "\\,")) for k, v in data.items())


def cmd_save():
    req = json.loads(sys.stdin.readline() or "{}")
    name = str(req.get("name", "")).strip()
    gateway = str(req.get("gateway", "")).strip()
    protocol = str(req.get("protocol", "anyconnect")).strip() or "anyconnect"
    if not name or not gateway:
        emit("error", text="Name and gateway are required")
        sys.exit(1)
    if protocol not in PROTOCOLS:
        emit("error", text="Unknown protocol: %s" % protocol)
        sys.exit(1)
    uuid = str(req.get("uuid") or "")
    data = vpn_data(uuid) if uuid else dict(NEW_PROFILE_DATA)
    gateway_changed = data.get("gateway") != gateway
    data["gateway"] = gateway
    data["protocol"] = protocol
    usergroup = str(req.get("usergroup", "")).strip()
    if usergroup:
        data["usergroup"] = usergroup
    else:
        data.pop("usergroup", None)
    reported_os = str(req.get("reportedOs", "")).strip()
    if reported_os:
        data["reported_os"] = reported_os
    else:
        data.pop("reported_os", None)
    # GlobalProtect HIP report: NM runs openconnect's bundled hipreport.sh.
    if protocol == "gp" and req.get("hip"):
        data["csd_wrapper"] = HIP_WRAPPER
        data["enable_csd_trojan"] = "yes"
    else:
        data.pop("csd_wrapper", None)
        data["enable_csd_trojan"] = "no"

    # Split tunnel: never make the VPN the default route. NM then also stops
    # sending every DNS lookup to the VPN's resolvers (they only get the
    # VPN's own domains), which is what breaks general internet access when
    # those resolvers aren't reachable.
    never_default = "yes" if req.get("splitTunnel") else "no"
    routing = ["ipv4.never-default", never_default, "ipv6.never-default", never_default]
    if uuid:
        res = nmcli("connection", "modify", uuid, "connection.id", name, "vpn.data", format_vpn_data(data), *routing)
    else:
        res = nmcli("connection", "add", "type", "vpn", "con-name", name, "vpn-type", "openconnect",
                    "connection.autoconnect", "no", "vpn.data", format_vpn_data(data), *routing)
        m = re.search(r"\(([0-9a-f-]{36})\)", res.stdout)
        uuid = m.group(1) if m else ""
    if res.returncode != 0 or not uuid:
        emit("error", text=(res.stderr.strip().splitlines() or ["nmcli failed"])[-1])
        sys.exit(1)

    state = load_state()
    conn = state.setdefault(uuid, {})
    if gateway_changed:
        conn.pop("servercert", None)
    username = str(req.get("username", "")).strip()
    if username:
        conn["username"] = username
    else:
        conn.pop("username", None)
    remember = bool(req.get("rememberPassword"))
    password = req.get("password") or ""
    if not remember:
        keyring_clear(uuid)
    elif password:
        if not keyring_set(uuid, name, password):
            remember = False
            emit("error", text="Could not store the password in the keyring")
    elif not keyring_get(uuid):
        remember = False
    conn["rememberPassword"] = remember
    conn["sso"] = bool(req.get("sso")) and protocol in SSO_PROTOCOLS
    save_state(state)
    emit("saved", uuid=uuid)


def cmd_delete(uuid):
    res = nmcli("connection", "delete", uuid)
    keyring_clear(uuid)
    state = load_state()
    state.pop(uuid, None)
    save_state(state)
    if res.returncode != 0:
        sys.stderr.write(res.stderr)
    sys.exit(res.returncode)


class Session:
    def __init__(self, uuid):
        self.uuid = uuid
        self.data = vpn_data(uuid)
        self.state = load_state()
        self.conn_state = self.state.setdefault(uuid, {})
        self.gateway = self.data.get("gateway", "")
        self.buf = ""          # pending partial line (possible prompt)
        self.messages = []     # meaningful lines since the last prompt
        self.swallow = False   # drop the echo / newline after an answer
        self.stdin_buf = ""
        self.autofilled = set()     # prompt labels already answered from saved data
        self.new_password = None    # (password, remember) typed by the user this session
        self.protocol = self.data.get("protocol") or "anyconnect"
        self.sso = bool(self.conn_state.get("sso")) and self.protocol in SSO_PROTOCOLS
        self.saml_required = False
        self.child = None
        self.redact = ""  # secret typed via --passwd-on-stdin; never logged

    def build_cmd(self, extra=()):
        d = self.data
        cmd = ["openconnect", "--authenticate", "--protocol", self.protocol, *extra]
        pin = self.conn_state.get("servercert")
        if pin:
            cmd += ["--servercert", pin]
        if d.get("usergroup") and "--usergroup" not in extra:
            cmd += ["--usergroup", d["usergroup"]]
        if d.get("useragent"):
            cmd += ["--useragent", d["useragent"]]
        if d.get("reported_os"):
            cmd += ["--os", d["reported_os"]]
        if d.get("cacert"):
            cmd += ["--cafile", d["cacert"]]
        if d.get("usercert"):
            cmd += ["--certificate", d["usercert"]]
        if d.get("userkey"):
            cmd += ["--sslkey", d["userkey"]]
        if d.get("proxy"):
            cmd += ["--proxy", d["proxy"]]
        cmd.append(self.gateway)
        return cmd

    def read_answer(self):
        """Block until the UI sends an answer line. Returns None on cancel/EOF."""
        while "\n" not in self.stdin_buf:
            chunk = os.read(0, 4096)
            if not chunk:
                return None
            self.stdin_buf += chunk.decode(errors="replace")
        line, self.stdin_buf = self.stdin_buf.split("\n", 1)
        try:
            msg = json.loads(line)
        except ValueError:
            return None
        if msg.get("cancel"):
            return None
        return msg

    def handle_line(self, line):
        line = line.rstrip("\r")
        if self.redact and self.redact in line:
            return
        if self.swallow:
            self.swallow = False
            return
        m = re.search(r"pin-sha256:[A-Za-z0-9+/=]+", line)
        if m:
            self.pending_pin = m.group(0)
        if re.search(r"SAML .*authentication (is )?required|SAML REDIRECT|No SSO handler", line):
            self.saml_required = True
        if not line.strip() or NOISE.search(line):
            return
        self.messages.append(line.strip())
        emit("log", text=line.strip())

    def prompt(self, master, label):
        label = label.strip()
        attrs = termios.tcgetattr(master)
        secret = not (attrs[3] & termios.ECHO)
        kind = "text"
        choices = []
        if "to accept" in label:
            kind = "cert"
        else:
            m = re.search(r"\[([^\]]*\|[^\]]*)\]\s*:?\s*$", label)
            if m:
                choices = [c for c in m.group(1).split("|") if c]
                label = label[:m.start()].strip()
        label = label.rstrip(":").strip()
        message = "\n".join(self.messages[-3:])
        self.messages = []
        self.swallow = True
        is_user = kind == "text" and not secret and not choices and re.search(r"user|login|e-?mail", label, re.I)
        # Only a plain "Password" field may be answered from the keyring —
        # never a challenge (SMS / MFA / "Response") prompt.
        is_password = kind == "text" and secret and not choices and re.search(r"pass(word|code)?\b", label, re.I) \
            and not re.search(r"code|token|otp|verif|response|answer|pin\b", label, re.I)

        # Auto-answer once per label; seeing the same label again means the
        # server rejected it, so fall through to asking the user.
        if is_user and self.conn_state.get("username") and label not in self.autofilled:
            self.autofilled.add(label)
            emit("log", text="Signing in as %s" % self.conn_state["username"])
            return self.conn_state["username"]
        if is_password and self.conn_state.get("rememberPassword") and label not in self.autofilled:
            self.autofilled.add(label)
            saved = keyring_get(self.uuid)
            if saved:
                emit("log", text="Using saved password")
                return saved
        if label in self.autofilled and not message:
            message = "The saved %s was rejected." % label.lower()

        emit("prompt", label=label, secret=secret, kind=kind, message=message, choices=choices,
             pin=getattr(self, "pending_pin", ""),
             value=self.conn_state.get("username", "") if is_user else "",
             canRemember=bool(is_password),
             remember=bool(self.conn_state.get("rememberPassword")))
        msg = self.read_answer()
        if msg is None:
            return None
        answer = str(msg.get("answer", ""))
        if is_user:
            self.conn_state["username"] = answer
        if is_password:
            self.new_password = (answer, bool(msg.get("remember")))
        if kind == "cert" and answer.lower() == "yes" and getattr(self, "pending_pin", ""):
            self.conn_state["servercert"] = self.pending_pin
        return answer

    def store_password(self):
        """Apply the remember-password choice once the server accepted the login."""
        if not self.new_password:
            return
        password, remember = self.new_password
        self.new_password = None
        if remember and password:
            name = nmcli("-g", "connection.id", "connection", "show", self.uuid).stdout.strip() or self.gateway
            self.conn_state["rememberPassword"] = keyring_set(self.uuid, name, password)
        elif not remember:
            keyring_clear(self.uuid)
            self.conn_state["rememberPassword"] = False

    def authenticate(self, extra=(), preinput=None):
        master, slave = pty.openpty()
        out_r, out_w = os.pipe()
        proc = subprocess.Popen(self.build_cmd(extra), stdin=slave, stderr=slave, stdout=out_w,
                                start_new_session=True, env=dict(os.environ, LC_ALL="C"))
        self.child = proc
        if preinput is not None:
            # --passwd-on-stdin: type it with echo off so it never reaches the log.
            attrs = termios.tcgetattr(slave)
            quiet = list(attrs)
            quiet[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, quiet)
            self.redact = preinput
            os.write(master, (preinput + "\n").encode())
            time.sleep(0.3)  # pty input is processed asynchronously; let it drain
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
        os.close(slave)
        os.close(out_w)
        stdout = b""
        fds = [master, out_r]
        emit("state", state="authenticating")
        try:
            while fds:
                ready, _, _ = select.select(fds, [], [], 0.35)
                if not ready:
                    if self.buf and proc.poll() is None:
                        label, self.buf = self.buf, ""
                        answer = self.prompt(master, label)
                        if answer is None:
                            proc.terminate()
                            return None
                        os.write(master, (answer + "\n").encode())
                    elif proc.poll() is not None and master not in fds:
                        break
                    continue
                for fd in ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        fds.remove(fd)
                        continue
                    if fd == out_r:
                        stdout += chunk
                        continue
                    self.buf += chunk.decode(errors="replace")
                    while "\n" in self.buf:
                        line, self.buf = self.buf.split("\n", 1)
                        self.handle_line(line)
        finally:
            proc.wait()
            os.close(master)
            os.close(out_r)
            if proc.returncode == 0:
                self.store_password()
            save_state(self.state)
        if proc.returncode != 0:
            if self.saml_required and not self.sso:
                emit("error", text="This server uses browser single sign-on. Edit the connection and set Sign-in to Browser SSO.")
                return None
            tail = [m for m in self.messages if m] or ["Authentication failed"]
            emit("error", text=tail[-1])
            return None
        result = {}
        for line in stdout.decode(errors="replace").splitlines():
            m = re.match(r"^([A-Z_]+)='?(.*?)'?$", line)
            if m:
                result[m.group(1)] = m.group(2).replace("'\\''", "'")
        if not result.get("COOKIE"):
            emit("error", text="Server did not return a session cookie")
            return None
        return result

    # ----- single sign-on -------------------------------------------------

    def run_login(self):
        if not self.sso:
            return self.authenticate()
        if self.protocol == "anyconnect":
            emit("state", state="browser")
            return self.authenticate(extra=("--external-browser", "xdg-open"))
        if self.protocol == "gp":
            return self.gp_sso()
        if self.protocol == "fortinet":
            return self.fortinet_sso()
        return self.authenticate()

    def gp_sso(self):
        """GlobalProtect SAML via gpauth (globalprotect-openconnect) in the default browser."""
        if not shutil.which("gpauth"):
            emit("error", text="GlobalProtect SSO needs gpauth: omarchy pkg add globalprotect-openconnect")
            return None
        gateway_mode = self.data.get("usergroup", "").startswith("gateway")
        cmd = ["gpauth", self.gateway, "--browser", "default",
               "--os", GPAUTH_OS.get(self.data.get("reported_os", ""), "Linux")]
        if gateway_mode:
            cmd.append("--gateway")
        if self.conn_state.get("servercert"):
            cmd.append("--ignore-tls-errors")
        emit("state", state="browser")
        self.child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                      start_new_session=True)
        try:
            out, err = self.child.communicate(timeout=SSO_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.child.kill()
            emit("error", text="Timed out waiting for the browser sign-in")
            return None
        if self.child.returncode != 0:
            lines = [l for l in (err or "").splitlines() if l.strip()]
            emit("error", text=(lines[-1] if lines else "GlobalProtect sign-in failed")[:200])
            return None
        found = {}

        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key = k.replace("_", "-").lower()
                    if isinstance(v, str) and v:
                        found.setdefault(key, v)
                    walk(v)
        try:
            walk(json.loads(out.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            emit("error", text="Unexpected response from gpauth")
            return None
        username = found.get("username") or found.get("saml-username", "")
        for field in ("prelogin-cookie", "portal-userauthcookie"):
            if found.get(field):
                group = "%s:%s" % ("gateway" if gateway_mode else "portal", field)
                emit("log", text="Signed in as %s" % username if username else "Signed in")
                return self.authenticate(extra=("--user", username, "--usergroup", group, "--passwd-on-stdin"),
                                         preinput=found[field])
        emit("error", text="gpauth did not return a login cookie")
        return None

    def fortinet_base(self):
        gw = re.sub(r"^https?://", "", self.gateway).split("/")[0]
        return gw, "https://" + gw

    def curl_pin_args(self):
        pin = self.conn_state.get("servercert", "")
        if pin.startswith("pin-sha256:"):
            return ["-k", "--pinnedpubkey", "sha256//" + pin[len("pin-sha256:"):]]
        return []

    def server_pin(self, hostport):
        host, _, port = hostport.partition(":")
        script = ("openssl s_client -connect \"$1:$2\" -servername \"$1\" </dev/null 2>/dev/null"
                  " | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der"
                  " | openssl dgst -sha256 -binary | base64")
        res = subprocess.run(["sh", "-c", script, "sh", host, port or "443"], capture_output=True, text=True, timeout=20)
        pin = res.stdout.strip()
        return "pin-sha256:" + pin if res.returncode == 0 and len(pin) > 40 else ""

    def fortinet_trust(self, hostport, base):
        """Make sure curl can talk to the FortiGate; ask to trust a self-signed cert."""
        probe = ["curl", "-sS", "-o", "/dev/null", "--max-time", "15", *self.curl_pin_args(), base + "/remote/login"]
        res = subprocess.run(probe, capture_output=True, text=True)
        if res.returncode == 0:
            return True
        if res.returncode not in (35, 51, 58, 60, 90):
            emit("error", text=(res.stderr.strip() or "Cannot reach %s" % hostport)[:200])
            return False
        pin = self.server_pin(hostport)
        if not pin:
            emit("error", text="Could not read the gateway certificate")
            return False
        self.pending_pin = pin
        emit("prompt", label="Trust certificate", secret=False, kind="cert", message="", choices=[], pin=pin,
             value="", canRemember=False, remember=False)
        msg = self.read_answer()
        if not msg or str(msg.get("answer", "")).lower() != "yes":
            return False
        self.conn_state["servercert"] = pin
        save_state(self.state)
        return True

    def fortinet_sso(self):
        """FortiGate SAML: the browser signs in and FortiGate redirects to
        http://127.0.0.1:8020/?id=…, which we trade for the SVPNCOOKIE."""
        hostport, base = self.fortinet_base()
        emit("state", state="authenticating")
        if not self.fortinet_trust(hostport, base):
            return None
        result = {}
        done = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                if "id" in query:
                    result["id"] = query["id"][0]
                    done.set()
                body = (b"<!doctype html><meta charset=utf-8><title>VPN</title>"
                        b"<body style='font-family:sans-serif;background:#1a1b26;color:#c0caf5;"
                        b"display:grid;place-items:center;height:100vh;margin:0'>"
                        b"<p>Signed in. You can close this tab and return to your desktop.</p>")
                self.send_response(200 if "id" in query else 404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        try:
            server = HTTPServer(("127.0.0.1", FORTINET_SSO_PORT), Handler)
        except OSError:
            emit("error", text="Port %d is busy (is FortiClient running?)" % FORTINET_SSO_PORT)
            return None
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            emit("state", state="browser")
            subprocess.Popen(["xdg-open", base + "/remote/saml/start?redirect=1"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not done.wait(SSO_TIMEOUT):
                emit("error", text="Timed out waiting for the browser sign-in")
                return None
        finally:
            server.shutdown()
        emit("state", state="authenticating")
        res = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-D", "-", "--max-time", "20", *self.curl_pin_args(),
                              base + "/remote/saml/auth_id?id=" + urllib.parse.quote(result["id"])],
                             capture_output=True, text=True)
        m = re.search(r"^set-cookie:\s*SVPNCOOKIE=([^;\s]+)", res.stdout, re.I | re.M)
        if not m:
            emit("error", text="FortiGate did not issue a session cookie")
            return None
        auth = {"COOKIE": "SVPNCOOKIE=" + m.group(1), "HOST": hostport}
        if self.conn_state.get("servercert"):
            auth["FINGERPRINT"] = self.conn_state["servercert"]
        return auth

    def connect(self, auth):
        emit("state", state="connecting")
        fd, path = tempfile.mkstemp(prefix="oc-", dir=os.environ.get("XDG_RUNTIME_DIR"))
        try:
            with os.fdopen(fd, "w") as f:
                f.write("vpn.secrets.cookie:%s\n" % auth["COOKIE"])
                f.write("vpn.secrets.gateway:%s\n" % (auth.get("CONNECT_URL") or auth.get("HOST") or self.gateway))
                if auth.get("FINGERPRINT"):
                    f.write("vpn.secrets.gwcert:%s\n" % auth["FINGERPRINT"])
                if auth.get("RESOLVE"):
                    f.write("vpn.secrets.resolve:%s\n" % auth["RESOLVE"])
            res = nmcli("--wait", "60", "connection", "up", self.uuid, "passwd-file", path)
        finally:
            os.unlink(path)
        if res.returncode != 0:
            emit("error", text=(res.stderr.strip().splitlines() or ["NetworkManager failed to connect"])[-1])
            return False
        self.conn_state["lastUsed"] = int(time.time())
        save_state(self.state)
        emit("state", state="connected")
        return True


def cmd_connect(uuid):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    session = Session(uuid)

    def on_term(signum, frame):
        # Cancel from the UI: take openconnect / gpauth down with us.
        child = session.child
        if child and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except OSError:
                pass
        emit("state", state="cancelled")
        os._exit(1)
    signal.signal(signal.SIGTERM, on_term)

    if not session.gateway:
        emit("error", text="Connection has no gateway configured")
        sys.exit(1)
    auth = session.run_login()
    if auth is None:
        emit("state", state="cancelled")
        sys.exit(1)
    sys.exit(0 if session.connect(auth) else 1)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "list":
        cmd_list()
    elif cmd == "connect" and len(sys.argv) > 2:
        cmd_connect(sys.argv[2])
    elif cmd == "disconnect" and len(sys.argv) > 2:
        cmd_disconnect(sys.argv[2])
    elif cmd == "save":
        cmd_save()
    elif cmd == "delete" and len(sys.argv) > 2:
        cmd_delete(sys.argv[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
