#!/usr/bin/env python3
"""Backend for the VPN bar widget (OpenConnect and OpenVPN).

  helper.py list              JSON list of VPN profiles: NetworkManager OpenConnect
                              and OpenVPN connections, plus OpenVPN 3 (SSO) profiles
  helper.py connect <id>      Interactive login; JSON events on stdout,
                              JSON answers on stdin ({"answer": "..."} / {"cancel": true})
  helper.py disconnect <id>
  helper.py save              Create / update a profile from JSON on stdin
  helper.py delete <id>
  helper.py pick-file         Native file dialog for an .ovpn file; JSON {"path": ...}

Profile ids are NetworkManager UUIDs, or "ovpn3:<config id>" for OpenVPN 3
profiles (used for browser SSO / SAML, which NetworkManager's OpenVPN plugin
can't do).

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
OPENCONNECT_SERVICE = "org.freedesktop.NetworkManager.openconnect"
OPENVPN_SERVICE = "org.freedesktop.NetworkManager.openvpn"
OVPN3_PREFIX = "ovpn3:"
OVPN3_CONFIG_ROOT = "/net/openvpn/v3/configuration/"
# NM-OpenVPN connection types that take a username / password.
OPENVPN_PASSWORD_TYPES = ("password", "password-tls")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
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
        service = nmcli("-g", "vpn.service-type", "connection", "show", uuid).stdout.strip()
        if service not in (OPENCONNECT_SERVICE, OPENVPN_SERVICE):
            continue
        data = vpn_data(uuid)
        conn_state = state.get(uuid, {})
        entry = {
            "name": name,
            "uuid": uuid,
            "backend": "openconnect",
            "gateway": data.get("gateway", ""),
            "protocol": data.get("protocol", "anyconnect"),
            "state": active.get(uuid, ""),
            "usergroup": data.get("usergroup", ""),
            "username": conn_state.get("username", ""),
            "rememberPassword": bool(conn_state.get("rememberPassword")),
            "sso": bool(conn_state.get("sso")),
            "hip": data.get("enable_csd_trojan") == "yes" and bool(data.get("csd_wrapper")),
            "reportedOs": data.get("reported_os", ""),
            "lastUsed": conn_state.get("lastUsed", 0),
            "splitTunnel": nmcli("-g", "ipv4.never-default", "connection", "show", uuid).stdout.strip() == "yes",
        }
        if service == OPENVPN_SERVICE:
            entry.update({
                "backend": "nm-openvpn", "protocol": "openvpn", "usergroup": "", "sso": False, "hip": False,
                "reportedOs": "", "gateway": openvpn_remote(data.get("remote", "")),
                # NM-OpenVPN keeps the username in the profile itself.
                "username": data.get("username", ""),
                "needsPassword": data.get("connection-type", "") in OPENVPN_PASSWORD_TYPES,
            })
        conns.append(entry)
    conns += ovpn3_profiles(state)
    json.dump({"ok": res.returncode == 0, "error": res.stderr.strip(), "connections": conns,
               "openvpn": {"nm": os.path.exists("/usr/lib/NetworkManager/VPN/nm-openvpn-service.name"),
                           "openvpn3": bool(shutil.which("openvpn3"))}}, sys.stdout)


def openvpn_remote(remote):
    """First server of an NM-OpenVPN "remote" list (host[:port[:proto]], comma-separated)."""
    first = remote.split(",")[0].strip()
    parts = first.split(":")
    return ":".join(parts[:2]) if len(parts) > 1 and parts[1] not in ("", "1194") else parts[0]


# ----- OpenVPN 3 (browser SSO / SAML) ------------------------------------------
#
# NetworkManager's OpenVPN plugin can't do OpenVPN web authentication
# (WEB_AUTH / OPEN_URL), so SSO profiles live in openvpn3-linux instead. It runs
# unprivileged over D-Bus and announces IV_SSO=webauth to the server.

OVPN3_CONNECTED = 7   # StatusMinor CONN_CONNECTED on net.openvpn.v3.sessions


def ovpn3_id(config_path):
    return OVPN3_PREFIX + config_path.rsplit("/", 1)[-1]


def ovpn3_path(profile_id):
    return OVPN3_CONFIG_ROOT + profile_id[len(OVPN3_PREFIX):]


def ovpn3_run(*args, **kw):
    return subprocess.run(["openvpn3", *args], capture_output=True, text=True, **kw)


def ovpn3_sessions():
    """{config path: (session path, status minor)} for this user's OpenVPN 3 sessions."""
    if not shutil.which("openvpn3"):
        return {}
    try:
        from gi.repository import Gio, GLib
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM)
        paths = bus.call_sync("net.openvpn.v3.sessions", "/net/openvpn/v3/sessions", "net.openvpn.v3.sessions",
                              "FetchAvailableSessions", None, None, 0, 5000, None).unpack()[0]
        out = {}
        for path in paths:
            def prop(name):
                return bus.call_sync("net.openvpn.v3.sessions", path, "org.freedesktop.DBus.Properties", "Get",
                                     GLib.Variant("(ss)", ("net.openvpn.v3.sessions", name)), None, 0, 5000,
                                     None).unpack()[0]
            out[prop("config_path")] = (path, prop("status")[1])
        return out
    except Exception:
        return {}


def ovpn3_remote(path):
    """Server address from an imported profile (for display only)."""
    res = ovpn3_run("config-dump", "--path", path)
    m = re.search(r"^\s*remote\s+(\S+)(?:\s+(\d+))?", res.stdout, re.M)
    if not m:
        return ""
    return m.group(1) + (":" + m.group(2) if m.group(2) and m.group(2) != "1194" else "")


def ovpn3_profiles(state):
    if not shutil.which("openvpn3"):
        return []
    res = ovpn3_run("configs-list", "--json")
    try:
        configs = json.loads(res.stdout or "{}")
    except ValueError:
        return []
    sessions = ovpn3_sessions()
    out = []
    for path, cfg in sorted(configs.items(), key=lambda kv: kv[1].get("name", "")):
        pid = ovpn3_id(path)
        conn_state = state.get(pid, {})
        session = sessions.get(path)
        out.append({
            "name": cfg.get("name", ""), "uuid": pid, "backend": "openvpn3", "protocol": "openvpn",
            "gateway": conn_state.get("gateway") or ovpn3_remote(path),
            "state": ("activated" if session[1] == OVPN3_CONNECTED else "activating") if session else "",
            "usergroup": "", "username": "", "rememberPassword": False, "sso": True, "hip": False,
            "reportedOs": "", "lastUsed": conn_state.get("lastUsed", 0), "splitTunnel": False,
            "needsPassword": False,
        })
    return out


def is_ovpn3(uuid):
    return uuid.startswith(OVPN3_PREFIX)


def nm_service(uuid):
    return nmcli("-g", "vpn.service-type", "connection", "show", uuid).stdout.strip()


def cmd_disconnect(uuid):
    if is_ovpn3(uuid):
        session = ovpn3_sessions().get(ovpn3_path(uuid))
        if not session:
            sys.exit(0)
        res = ovpn3_run("session-manage", "--path", session[0], "--disconnect")
    else:
        res = nmcli("connection", "down", uuid)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or res.stdout)
    sys.exit(res.returncode)


def format_vpn_data(data):
    return ", ".join("%s = %s" % (k, str(v).replace(",", "\\,")) for k, v in data.items())


def cmd_save():
    req = json.loads(sys.stdin.readline() or "{}")
    name = str(req.get("name", "")).strip()
    gateway = str(req.get("gateway", "")).strip()
    protocol = str(req.get("protocol", "anyconnect")).strip() or "anyconnect"
    if protocol == "openvpn":
        return save_openvpn(req, name)
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


def apply_password_choice(uuid, name, conn, req):
    """Keyring handling shared by all profile types; returns the final remember flag."""
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
    return remember


def save_openvpn(req, name):
    """OpenVPN profiles come from an .ovpn file: into NetworkManager for
    password / certificate sign-in, into OpenVPN 3 for browser SSO."""
    if not name:
        emit("error", text="Name is required")
        sys.exit(1)
    uuid = str(req.get("uuid") or "")
    if not uuid:
        path = os.path.expanduser(str(req.get("ovpnFile", "")).strip())
        if not path or not os.path.isfile(path):
            emit("error", text="Choose the .ovpn file your VPN provider gave you")
            sys.exit(1)
        if req.get("sso"):
            if not shutil.which("openvpn3"):
                emit("error", text="Browser SSO for OpenVPN needs OpenVPN 3: omarchy pkg aur add openvpn3")
                sys.exit(1)
            res = ovpn3_run("config-import", "--config", path, "--name", name, "--persistent")
            m = re.search(r"(/net/openvpn/v3/configuration/\S+)", res.stdout)
            if res.returncode != 0 or not m:
                emit("error", text=((res.stderr or res.stdout).strip().splitlines() or ["Import failed"])[-1])
                sys.exit(1)
            uuid = ovpn3_id(m.group(1))
        else:
            if not os.path.exists("/usr/lib/NetworkManager/VPN/nm-openvpn-service.name"):
                emit("error", text="OpenVPN needs NetworkManager's plugin: omarchy pkg add networkmanager-openvpn")
                sys.exit(1)
            res = nmcli("connection", "import", "type", "openvpn", "file", path)
            m = re.search(r"\(([0-9a-f-]{36})\)", res.stdout)
            if res.returncode != 0 or not m:
                emit("error", text=((res.stderr or res.stdout).strip().splitlines() or ["Import failed"])[-1])
                sys.exit(1)
            uuid = m.group(1)

    state = load_state()
    conn = state.setdefault(uuid, {})
    if is_ovpn3(uuid):
        path = ovpn3_path(uuid)
        current = json.loads(ovpn3_run("configs-list", "--json").stdout or "{}").get(path, {})
        if current.get("name") != name:
            res = ovpn3_run("config-manage", "--path", path, "--rename", name)
            if res.returncode != 0:
                emit("error", text=((res.stderr or res.stdout).strip().splitlines() or ["Rename failed"])[-1])
                sys.exit(1)
        conn["sso"] = True
        conn.pop("rememberPassword", None)
        save_state(state)
        emit("saved", uuid=uuid)
        return

    data = vpn_data(uuid)
    if data.get("connection-type", "") in OPENVPN_PASSWORD_TYPES:
        # Never let NetworkManager store the password itself: it is asked for
        # at every connect, and remembered only in the keyring.
        data["password-flags"] = "2"
        username = str(req.get("username", "")).strip()
        if username:
            data["username"] = username
        else:
            data.pop("username", None)
    never_default = "yes" if req.get("splitTunnel") else "no"
    res = nmcli("connection", "modify", uuid, "connection.id", name, "connection.autoconnect", "no",
                "vpn.data", format_vpn_data(data),
                "ipv4.never-default", never_default, "ipv6.never-default", never_default)
    if res.returncode != 0:
        emit("error", text=(res.stderr.strip().splitlines() or ["nmcli failed"])[-1])
        sys.exit(1)
    conn["sso"] = False
    apply_password_choice(uuid, name, conn, req)
    save_state(state)
    emit("saved", uuid=uuid)


def cmd_delete(uuid):
    if is_ovpn3(uuid):
        path = ovpn3_path(uuid)
        session = ovpn3_sessions().get(path)
        if session:
            ovpn3_run("session-manage", "--path", session[0], "--disconnect")
        res = ovpn3_run("config-remove", "--path", path, "--force")
    else:
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


class PtyLogin:
    """Drives an interactive CLI (nmcli --ask, openvpn3 session-start) on a pty.
    A partial line that stays idle is a prompt: it goes to the panel as a JSON
    event, and the answer is typed back."""

    read_answer = Session.read_answer   # same wire format as the OpenConnect login

    def __init__(self, uuid):
        self.uuid = uuid
        self.state = load_state()
        self.conn_state = self.state.setdefault(uuid, {})
        self.stdin_buf = ""
        self.child = None
        self.messages = []       # meaningful output since the last prompt
        self.last_answer = None  # swallow the echo of what was just typed
        self.error = ""
        self.new_password = None

    def ask(self, label, message="", secret=False, value="", can_remember=False, remember=False):
        emit("prompt", label=label, secret=secret, kind="text", message=message, choices=[], pin="",
             value=value, canRemember=can_remember, remember=remember)
        return self.read_answer()

    def run_pty(self, cmd):
        """Returns the exit code, or None when the user cancelled a prompt."""
        master, slave = pty.openpty()
        proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                                env=dict(os.environ, LC_ALL="C"))
        self.child = proc
        os.close(slave)
        buf = ""
        try:
            while True:
                ready, _, _ = select.select([master], [], [], 0.35)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        break
                    buf += ANSI.sub("", chunk.decode(errors="replace")).replace("\r", "")
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        self.line(line.strip())
                elif buf.strip() and proc.poll() is None:
                    label, buf = buf.strip(), ""
                    answer = self.on_prompt(label, master)
                    if answer is None:
                        self.abort()
                        return None
                    self.last_answer = answer
                    os.write(master, (answer + "\n").encode())
                elif proc.poll() is not None:
                    break
        finally:
            proc.wait()
            os.close(master)
        return proc.returncode

    def line(self, text):
        if not text:
            return
        if self.last_answer is not None and (text == self.last_answer or re.fullmatch(r"\*+", text)):
            self.last_answer = None
            return
        self.last_answer = None
        self.on_line(text)

    def abort(self):
        child = self.child
        if child and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except OSError:
                pass

    def store_password(self, name):
        if not self.new_password:
            return
        password, remember = self.new_password
        self.new_password = None
        if remember and password:
            self.conn_state["rememberPassword"] = keyring_set(self.uuid, name, password)
        elif not remember:
            keyring_clear(self.uuid)
            self.conn_state["rememberPassword"] = False

    def succeeded(self):
        self.conn_state["lastUsed"] = int(time.time())
        save_state(self.state)
        emit("state", state="connected")
        return True


class NMOpenVPNLogin(PtyLogin):
    """OpenVPN through NetworkManager (username / password, certificates, and
    dynamic challenges such as OTP codes). `nmcli --ask` is the secret agent;
    its prompts look like `Password (vpn.secrets.password): `."""

    def __init__(self, uuid):
        super().__init__(uuid)
        self.data = vpn_data(uuid)
        self.name = nmcli("-g", "connection.id", "connection", "show", uuid).stdout.strip() or uuid
        self.rejected = False
        self.autofilled = False

    def on_line(self, text):
        if text.startswith(("You need to authenticate", "Connection successfully activated", "Warning:")):
            return
        if text.startswith("A password is required"):
            self.rejected = True   # NM asks again after the server refused the password
            return
        if text.startswith("Error:"):
            self.error = text[len("Error:"):].strip()
            return
        self.messages.append(text)
        emit("log", text=text)

    def on_prompt(self, label, master):
        m = re.match(r"^(.*?)\s*\(([^()]*)\)\s*:?$", label)
        text, key = (m.group(1).strip(), m.group(2)) if m else (label.rstrip(":").strip(), "")
        is_password = key == "vpn.secrets.password"
        challenge = "challenge" in key
        message = "\n".join(self.messages[-2:]) if challenge else ""
        self.messages = []
        rejected, self.rejected = self.rejected, False
        if is_password:
            if not rejected and not self.autofilled and self.conn_state.get("rememberPassword"):
                saved = keyring_get(self.uuid)
                if saved:
                    self.autofilled = True
                    emit("log", text="Using saved password")
                    return saved
            if rejected:
                message = "The saved password was rejected." if self.autofilled else "Wrong password, try again."
                self.autofilled = False
        msg = self.ask("Code" if challenge else text, message=message, secret="echo" not in key,
                       can_remember=is_password, remember=bool(self.conn_state.get("rememberPassword")))
        if msg is None:
            return None
        answer = str(msg.get("answer", ""))
        if is_password:
            self.new_password = (answer, bool(msg.get("remember")))
        return answer

    def abort(self):
        super().abort()
        nmcli("connection", "down", self.uuid)

    def run(self):
        if self.data.get("connection-type", "") in OPENVPN_PASSWORD_TYPES and not self.data.get("username"):
            msg = self.ask("Username", message="Sign in to %s" % self.name)
            if not msg or not str(msg.get("answer", "")).strip():
                return False
            username = str(msg["answer"]).strip()
            nmcli("connection", "modify", self.uuid, "+vpn.data", "username=%s" % username)
        emit("state", state="authenticating")
        rc = self.run_pty(["nmcli", "--ask", "--wait", str(SSO_TIMEOUT), "connection", "up", self.uuid])
        if rc is None:
            return False
        if rc != 0:
            # A failed activation keeps retrying in the background otherwise.
            nmcli("connection", "down", self.uuid)
            emit("error", text=self.error or (self.messages[-1] if self.messages else "Could not connect"))
            return False
        self.store_password(self.name)
        return self.succeeded()


class Ovpn3Login(PtyLogin):
    """OpenVPN 3 session with web authentication (SAML / SSO). session-start
    handles username / password / challenge prompts itself, then leaves the
    session waiting for the browser sign-in; the URL is read from
    `openvpn3 session-auth` and opened in the default browser."""

    def __init__(self, uuid):
        super().__init__(uuid)
        self.path = ovpn3_path(uuid)
        self.session_path = ""

    def on_line(self, text):
        m = re.match(r"Session path:\s*(\S+)", text)
        if m:
            self.session_path = m.group(1)
            return
        # session-start opens the sign-in page in the default browser by itself
        # (g_app_info_launch_default_for_uri); the browser's own chatter lands here too.
        if text.startswith(("Web based authentication required", "Session running, awaiting",
                            "Further manage this session", "Connected", "Opening in existing browser")):
            return
        self.messages.append(text)
        emit("log", text=text)

    def on_prompt(self, label, master):
        label = label.rstrip(":").strip()
        secret = not (termios.tcgetattr(master)[3] & termios.ECHO)
        message = "\n".join(self.messages[-2:])
        self.messages = []
        msg = self.ask(label, message=message, secret=secret)
        return None if msg is None else str(msg.get("answer", ""))

    def abort(self):
        super().abort()
        if self.session_path:
            ovpn3_run("session-manage", "--path", self.session_path, "--disconnect")

    def auth_url(self):
        out = ovpn3_run("session-auth").stdout
        for block in re.split(r"^-{10,}$", out, flags=re.M):
            if re.search(r"^\s*Path:\s*%s\s*$" % re.escape(self.session_path), block, re.M):
                m = re.search(r"^\s*Auth URL:\s*(\S+)", block, re.M)
                if m:
                    return m.group(1)
        return ""

    def run(self):
        existing = ovpn3_sessions().get(self.path)
        if existing and existing[1] == OVPN3_CONNECTED:
            return self.succeeded()
        if existing:
            ovpn3_run("session-manage", "--path", existing[0], "--disconnect")   # stale, half-open
        emit("state", state="authenticating")
        rc = self.run_pty(["openvpn3", "session-start", "--config-path", self.path])
        if rc is None:
            return False
        if not self.session_path:
            emit("error", text=self.messages[-1] if self.messages else "OpenVPN 3 could not start a session")
            return False
        announced = ""
        deadline = time.time() + SSO_TIMEOUT
        while time.time() < deadline:
            session = ovpn3_sessions().get(self.path)
            if not session:
                emit("error", text=self.messages[-1] if self.messages else "The VPN session ended")
                return False
            if session[1] == OVPN3_CONNECTED:
                return self.succeeded()
            url = self.auth_url()
            if url and url != announced:
                # The panel offers to open it again in case no browser came up.
                announced = url
                emit("state", state="browser", url=url)
            time.sleep(1)
        self.abort()
        emit("error", text="Timed out waiting for the browser sign-in")
        return False


def cmd_pick_file():
    """Native file dialog (xdg-desktop-portal FileChooser) for an OpenVPN profile."""
    from gi.repository import Gio, GLib
    bus = Gio.bus_get_sync(Gio.BusType.SESSION)
    token = "omarchy_vpn_%d" % os.getpid()
    handle = "/org/freedesktop/portal/desktop/request/%s/%s" % (bus.get_unique_name()[1:].replace(".", "_"), token)
    loop = GLib.MainLoop()
    result = {}

    def on_response(conn, sender, path, iface, name, params):
        code, results = params.unpack()
        if code == 0 and results.get("uris"):
            result["path"] = Gio.File.new_for_uri(results["uris"][0]).get_path()
        loop.quit()

    bus.signal_subscribe("org.freedesktop.portal.Desktop", "org.freedesktop.portal.Request", "Response", handle,
                         None, Gio.DBusSignalFlags.NONE, on_response)
    options = {
        "handle_token": GLib.Variant("s", token),
        "filters": GLib.Variant("a(sa(us))", [("OpenVPN profiles", [(0, "*.ovpn"), (0, "*.conf")]),
                                              ("All files", [(0, "*")])]),
    }
    downloads = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
    if downloads and os.path.isdir(downloads):
        options["current_folder"] = GLib.Variant("ay", downloads.encode() + b"\0")
    try:
        bus.call_sync("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
                      "org.freedesktop.portal.FileChooser", "OpenFile",
                      GLib.Variant("(ssa{sv})", ("", "Choose an OpenVPN profile", options)), None, 0, -1, None)
    except GLib.Error as e:
        json.dump({"error": e.message}, sys.stdout)
        return
    GLib.timeout_add_seconds(600, loop.quit)
    loop.run()
    json.dump(result, sys.stdout)


def cmd_connect(uuid):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    if is_ovpn3(uuid):
        session = Ovpn3Login(uuid)
    elif nm_service(uuid) == OPENVPN_SERVICE:
        session = NMOpenVPNLogin(uuid)
    else:
        session = Session(uuid)

    def on_term(signum, frame):
        # Cancel from the UI: take openconnect / gpauth / nmcli / openvpn3 down with us.
        if isinstance(session, PtyLogin):
            session.abort()
        else:
            child = session.child
            if child and child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except OSError:
                    pass
        emit("state", state="cancelled")
        os._exit(1)
    signal.signal(signal.SIGTERM, on_term)

    if isinstance(session, PtyLogin):
        ok = session.run()
        if not ok:
            emit("state", state="cancelled")
        sys.exit(0 if ok else 1)

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
    elif cmd == "pick-file":
        cmd_pick_file()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
