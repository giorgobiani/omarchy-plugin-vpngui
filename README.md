# omarchy-plugin-vpngui

All your VPNs in one place in the [Omarchy](https://omarchy.org/) bar:
Cisco AnyConnect and the other OpenConnect VPNs, plus OpenVPN. Password, SMS,
MFA and OTP prompts show up in the bar panel, so you don't need `nm-applet`
or a terminal.

| VPN | Sign-in |
|-----|---------|
| Cisco AnyConnect / ocserv | Password (+ code / token), or browser SSO |
| Palo Alto GlobalProtect | Password, or browser SSO (via `gpauth`) |
| Fortinet FortiGate | Password, or browser SSO |
| Juniper Network Connect, Pulse / Ivanti Secure, F5 BIG-IP, Array Networks | Password (+ code / token) |
| **OpenVPN** (from an `.ovpn` file) | Username & password, certificate, OTP / challenge codes, or browser SSO / SAML |

The tunnels are ordinary NetworkManager connections (OpenVPN browser SSO uses
OpenVPN 3, see below), so routes and DNS work the way they normally do, and
you never need `sudo`.

Plugin id: `shota.openconnect`

## Requirements

- Omarchy 4 (the Quickshell-based `omarchy-shell` with plugin support)
- NetworkManager (the Omarchy default)
- Packages:

  ```bash
  omarchy pkg add networkmanager-openconnect openconnect libsecret gnome-keyring
  ```

  `python`, `curl` and `openssl` are also used; they come with every Omarchy
  install.

- For **OpenVPN** with username / password or certificates:

  ```bash
  omarchy pkg add networkmanager-openvpn openvpn python-gobject
  ```

- For **OpenVPN browser SSO / SAML** (OpenVPN Access Server, CloudConnexa and
  other servers using OpenVPN web authentication), OpenVPN 3 from the AUR
  (the build takes a few minutes):

  ```bash
  omarchy pkg aur add openvpn3
  ```

  NetworkManager's OpenVPN plugin can't do OpenVPN web authentication, so
  SSO profiles run in [OpenVPN 3 Linux](https://github.com/OpenVPN/openvpn3-linux),
  OpenVPN's official client. It also runs without root, and uses
  systemd-resolved (the Omarchy default) for DNS.

- Optional, only for **GlobalProtect browser SSO**:

  ```bash
  omarchy pkg add globalprotect-openconnect
  ```

The editor warns you when a package it needs is missing.

## Install

```bash
omarchy plugin add https://github.com/giorgobiani/omarchy-plugin-vpngui.git --enable
```

`omarchy plugin add` shows a warning and asks you to confirm. Run in a
terminal, it also asks which bar section the widget goes in (the default is
right). The shield icon then shows up in the bar.

To move it later:

```bash
omarchy bar move shota.openconnect --section right
```

### Manual install

```bash
git clone https://github.com/giorgobiani/omarchy-plugin-vpngui.git \
  ~/.config/omarchy/plugins/shota.openconnect
omarchy-shell shell rescanPlugins
omarchy plugin enable shota.openconnect
```

The folder has to be named after the plugin id (`shota.openconnect`).

## Update / uninstall

```bash
omarchy plugin update shota.openconnect   # shows the diff, then fast-forwards
omarchy plugin remove shota.openconnect
```

Removing the plugin leaves your VPN profiles in NetworkManager (and OpenVPN
SSO profiles in OpenVPN 3: `openvpn3 configs-list`). To remove everything the
plugin stored:

```bash
rm -rf ~/.local/state/omarchy/plugins/shota.openconnect
secret-tool clear service omarchy-openconnect   # saved passwords
```

## Use

1. Click the shield icon (󰦞) in the bar.
2. Choose **Add your first VPN connection** and fill in:
   - **Name**: anything, e.g. `Work VPN`
   - **Gateway**: the server address your IT gave you, e.g. `vpn.example.com`
   - **Protocol**: *Cisco AnyConnect / ocserv* for Cisco
   - **Sign-in**: *Username & password*, or *Browser SSO* if your company
     signs in through Microsoft / Okta / Google
   - optionally a **Group**, **Username**, and **Remember password**
3. Click the connection. When the server asks for a password, an SMS code, or
   an authenticator code, the prompt appears in the panel. Type it in and
   press Enter.

### OpenVPN

1. Get the `.ovpn` file from your VPN provider or IT.
2. **Add connection** → set **Protocol** to *OpenVPN (.ovpn file)*.
3. Pick the file with **Browse…**, or type its path. The name is filled in
   from the file name.
4. Choose **Sign-in**:
   - *Username & password / certificate (+ code)*: imported into
     NetworkManager. Optionally enter the **Username** and turn on
     **Remember password**. If the server asks for an OTP / challenge code,
     the prompt appears in the panel with the server's own text. A
     certificate-only profile connects without any prompt.
   - *Browser SSO / SAML (OpenVPN 3)*: imported into OpenVPN 3. When you
     connect, the sign-in page opens in your default browser. Sign in there
     and the tunnel comes up. If no browser tab shows up, click **Open
     sign-in page** in the panel.
5. **Save**, then click the connection.

The sign-in type and the `.ovpn` file are fixed once imported. To change
them, delete the connection and add it again. You can still rename a
connection, change its username, split tunnel and saved password.

### Good to know

The first time you connect to an OpenConnect gateway whose certificate isn't signed by a
trusted authority, you're asked to trust it. The panel shows the
certificate's `pin-sha256`, and the pin is remembered for that profile.

When a prompt arrives while the panel is closed (for example an SMS that
takes a while), the panel opens by itself.

Profiles you already created in NetworkManager (`nm-connection-editor`,
`nmcli`) show up as well, as long as they are OpenConnect or OpenVPN
connections.

### Mouse and keys

| Action | What it does |
|--------|--------------|
| Left click on the icon | Open / close the panel |
| Middle click on the icon | Connect / disconnect the current or last used VPN |
| Toggle in the panel header | Same as middle click |
| `↑` `↓` / `j` `k`, `Enter` | Pick a connection, connect / disconnect |
| `n` | New connection |
| `e` | Edit the selected connection |
| `d` | Disconnect |
| `r` | Refresh |
| `Esc` | Cancel the login in progress, or close the panel |
| `Tab` | Switch to the next bar panel |

### Profile options

- **Split tunnel** only sends the networks the VPN server pushes through the
  tunnel. Your internet traffic and DNS stay on your own connection. Turn it
  on when you lose internet access while connected. It sets
  `ipv4.never-default` / `ipv6.never-default` on the NetworkManager
  connection. OpenVPN 3 has no equivalent, so OpenVPN SSO profiles always
  use the routes the server pushes.
- **Remember password** saves the password in your keyring. SMS, MFA and
  token codes are never stored.
- **GlobalProtect only:** *Connect to* (portal or gateway directly),
  *Report OS as*, and *Send HIP report* (the host-integrity check many
  GlobalProtect gateways require).
- **Group / Realm**: the AnyConnect group or FortiGate realm. Leave it empty
  and you'll be asked at login when the server offers a choice.

### Settings

| Key | Default | Range |
|-----|---------|-------|
| `refreshIntervalSec` | `10` | 3–600 |

```bash
omarchy bar set shota.openconnect refreshIntervalSec 30
```

### Keyboard shortcut

The widget has an IPC target, so you can bind it in
`~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + ALT + V", "VPN", "omarchy-shell shota.openconnect toggle")
```

## IPC

```bash
omarchy-shell shota.openconnect open | close | toggle | refresh
omarchy-shell shota.openconnect connect "<name or uuid>"
omarchy-shell shota.openconnect disconnect
omarchy-shell shota.openconnect cancel
omarchy-shell shota.openconnect add
omarchy-shell shota.openconnect edit "<name or uuid>"
omarchy-shell shota.openconnect status   # human-readable, e.g. "Connected · Work VPN"
omarchy-shell shota.openconnect phase    # idle | authenticating | browser | prompt | connecting
omarchy-shell shota.openconnect profiles # JSON: [{ uuid, name, protocol, state }]
```

`connect`, `edit` and `profiles` use NetworkManager UUIDs, or `ovpn3:<id>`
for OpenVPN SSO profiles.

[omarchy-plugin-rdpgui](https://github.com/giorgobiani/omarchy-plugin-rdpgui)
uses this to bring a VPN up before it opens a Remote Desktop session.

## How it works

`Panel.qml` is the bar widget and panel, `Service.qml` holds the state, and
`helper.py` does the actual work.

**OpenConnect:**

1. `openconnect --authenticate` runs on a pseudo-terminal. Every server
   prompt (username, password, SMS / MFA / token code, group choice,
   certificate trust) goes to the panel as a JSON event, and your answer goes
   back over stdin.
2. Browser SSO:
   - **AnyConnect**: `openconnect --external-browser xdg-open`
   - **GlobalProtect**: `gpauth --browser default`
   - **Fortinet**: your default browser signs in, FortiGate redirects to
     `http://127.0.0.1:8020/?id=…`, and that id is exchanged for the
     `SVPNCOOKIE` session cookie.
3. The session cookie goes to NetworkManager with
   `nmcli connection up <uuid> passwd-file <temp file>`, in a
   `$XDG_RUNTIME_DIR` file that is deleted right away. NetworkManager's
   OpenConnect plugin then brings up the tunnel.

**OpenVPN with password / certificate** runs `nmcli --ask connection up
<uuid>` on a pseudo-terminal. `nmcli` acts as NetworkManager's secret agent,
and its prompts (`Password (vpn.secrets.password)`, the challenge response
for OTP codes) are forwarded to the panel the same way. When the server
rejects a password, NetworkManager asks again, and you get "Wrong password".
A failed or cancelled attempt is always taken down with `nmcli connection
down`, so NetworkManager doesn't keep retrying in the background. The `.ovpn`
file is imported with `nmcli connection import type openvpn`, which copies
its certificates to `~/.local/share/networkmanagement/certificates/`.

**OpenVPN with browser SSO** uses OpenVPN 3. The `.ovpn` is imported with
`openvpn3 config-import --persistent`. `openvpn3 session-start` announces web
authentication to the server (`IV_SSO=webauth`), answers any
username / password prompts through the panel, and opens the server's
sign-in URL in the default browser. The helper reads that URL from `openvpn3
session-auth` (for the **Open sign-in page** button) and follows the session
over D-Bus (`net.openvpn.v3.sessions`) until it is connected.

## Storage and security

- **Profiles** are ordinary NetworkManager connections. OpenVPN SSO profiles
  are OpenVPN 3 configuration profiles, owned by your user.
- **`~/.local/state/omarchy/plugins/shota.openconnect/state.json`** (mode
  `0600`) holds the remembered username, the trusted certificate pin, the
  SSO / remember-password flags and the last-used time. It holds no secrets.
- **OpenVPN passwords** are never stored by NetworkManager: imported
  profiles are set to `password-flags=2` ("always ask"), and the plugin
  answers from the keyring when *Remember password* is on.
- **Passwords** are stored only in the Secret Service keyring
  (`service=omarchy-openconnect uuid=<uuid>`). They travel over stdin, never
  in command-line arguments, and are auto-filled only into a plain
  "Password" prompt, never into SMS / MFA / token prompts. A saved password
  that the server rejects isn't sent again; you're asked instead.
- Cookies passed with `--passwd-on-stdin` are typed with echo off and
  filtered out of all output.

Like every Omarchy plugin, this runs unsandboxed inside `omarchy-shell`.
Read the code before you enable it.

## Troubleshooting

- **"This server uses browser single sign-on"**: edit the connection and
  set *Sign-in* to *Browser SSO*.
- **Connected, but the internet stops working**: turn on *Split tunnel* for
  that connection.
- **"Remember password" doesn't stick**: a Secret Service keyring has to be
  running and unlocked (`gnome-keyring` on Omarchy).
- **GlobalProtect SSO**: `omarchy pkg add globalprotect-openconnect`.
- **OpenVPN: "Choose the .ovpn file …"**: the path is wrong or empty. `~` is
  fine.
- **OpenVPN: the import fails**: NetworkManager can't import some options.
  Check with `nmcli connection import type openvpn file <file>`. If your
  provider uses browser sign-in, import it as *Browser SSO / SAML* instead.
- **OpenVPN SSO: nothing happens in the browser**: click **Open sign-in
  page** in the panel. `openvpn3 session-auth` lists pending sign-ins, and
  `openvpn3 sessions-list` shows sessions.
- **OpenVPN SSO with AWS Client VPN**: not supported. AWS uses its own SAML
  flow that needs a patched OpenVPN client.
- **Browse… does nothing**: it uses the desktop portal's file dialog
  (`xdg-desktop-portal-gtk`) and `python-gobject`. You can type the path
  instead.
- **Fortinet SSO: "Port 8020 is busy"**: something else (usually
  FortiClient) is listening on `127.0.0.1:8020`.
- **Does the helper see your profiles?**

  ```bash
  python3 ~/.config/omarchy/plugins/shota.openconnect/helper.py list
  ```

- **Is the plugin loaded?** `omarchy plugin list | grep shota`

## License

[MIT](LICENSE)
