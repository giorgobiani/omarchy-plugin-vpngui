import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "shota.openconnect"
  ipcTarget: "shota.openconnect"
  manageIpc: false

  property int rowIndex: 0
  property bool cursorActive: false
  // Editor: editing opens the form; editUuid is "" for a new profile.
  property bool editing: false
  property string editUuid: ""

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property var prompt: vpn.prompt
  readonly property bool promptOpen: vpn.phase === "prompt" && prompt !== null
  readonly property var working: vpn.phase !== "idle" ? vpn.connectionByUuid(vpn.activeUuid) : null
  readonly property var heroConnection: vpn.connected || working || lastUsedConnection
  readonly property var lastUsedConnection: {
    var best = null
    for (var i = 0; i < vpn.connections.length; i++) {
      var c = vpn.connections[i]
      if (!best || (c.lastUsed || 0) > (best.lastUsed || 0)) best = c
    }
    return best
  }

  readonly property string heroMeta: {
    if (vpn.phase === "prompt") return "Waiting for you"
    if (vpn.phase === "authenticating") return "Signing in…"
    if (vpn.phase === "browser") return "Browser sign-in"
    if (vpn.phase === "connecting") return "Connecting…"
    if (vpn.connected) return "Connected · " + vpn.connected.name
    if (vpn.connections.length === 0) return "No VPN profiles"
    return "Disconnected · " + heroConnection.gateway
  }

  function activateRow(index) {
    if (index === vpn.connections.length) return startEdit("")
    var conn = vpn.connections[index]
    if (conn) vpn.toggle(conn.uuid)
  }

  function startEdit(uuid) {
    editUuid = uuid || ""
    editing = true
    editor.load(uuid ? vpn.connectionByUuid(uuid) : null)
  }

  function stopEdit() {
    editing = false
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    cursorActive = false
    vpn.refresh()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  // A prompt arriving while the panel is closed (slow SMS round-trip) pops it open.
  onPromptOpenChanged: if (promptOpen && !opened) open()

  Service {
    id: vpn
    settings: root.settings
    onSaved: function(uuid) { root.stopEdit() }
    onFilePicked: function(path) {
      editor.setFile(path)
      if (!root.opened) root.open()
    }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { vpn.refresh(); return "ok" }
    function status(): string { return root.heroMeta }
    // Machine-readable login state for other plugins: idle | authenticating | browser | prompt | connecting
    function phase(): string { return vpn.phase }
    // Every profile (OpenConnect, OpenVPN, OpenVPN 3) as JSON, for other plugins
    // such as Remote Desktop: [{ uuid, name, protocol, state }]
    function profiles(): string {
      var out = []
      for (var i = 0; i < vpn.connections.length; i++) {
        var c = vpn.connections[i]
        out.push({ uuid: c.uuid, name: c.name, protocol: c.protocol, state: c.state })
      }
      return JSON.stringify(out)
    }
    function connect(name: string): string {
      for (var i = 0; i < vpn.connections.length; i++) {
        var c = vpn.connections[i]
        if (c.name === name || c.uuid === name) { vpn.connect(c.uuid); root.open(); return "ok" }
      }
      return "not found"
    }
    function cancel(): string { vpn.cancel(); return "ok" }
    function add(): string { root.open(); root.startEdit(""); return "ok" }
    function edit(name: string): string {
      for (var i = 0; i < vpn.connections.length; i++) {
        var c = vpn.connections[i]
        if (c.name === name || c.uuid === name) { root.open(); root.startEdit(c.uuid); return "ok" }
      }
      return "not found"
    }
    function disconnect(): string {
      if (vpn.connected) vpn.disconnect(vpn.connected.uuid)
      return "ok"
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: vpn.connected ? "󰦝" : "󰦞"
    foreground: vpn.connected ? root.barForeground : Qt.darker(root.barForeground, 1.55)
    tooltipText: root.heroMeta
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.MiddleButton && root.heroConnection) vpn.toggle(root.heroConnection.uuid)
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(860))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // The editor and the prompt field own their keys (Esc included).
      blocked: (root.promptOpen && promptCard.fieldFocused) || (root.editing && !root.promptOpen)

      onMoveRequested: function(dx, dy) {
        if (!root.cursorActive) { root.cursorActive = true; return }
        if (dy === 0) return
        // Rows are the profiles followed by the "Add connection" row.
        root.rowIndex = Math.max(0, Math.min(vpn.connections.length, root.rowIndex + dy))
      }
      onActivateRequested: {
        if (root.promptOpen && root.prompt.kind === "cert") return vpn.answer("yes")
        if (root.cursorActive) root.activateRow(root.rowIndex)
      }
      onCloseRequested: {
        if (root.promptOpen) vpn.cancel()
        else root.close()
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "r" || t === "R") vpn.refresh()
        else if ((t === "d" || t === "D") && vpn.connected) vpn.disconnect(vpn.connected.uuid)
        else if (t === "n" || t === "N") root.startEdit("")
        else if ((t === "e" || t === "E") && vpn.connections[root.rowIndex]) root.startEdit(vpn.connections[root.rowIndex].uuid)
      }

      Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: parent.width
          spacing: Style.space(12)

          Item {
            id: header
            width: parent.width
            implicitHeight: hero.implicitHeight

            PanelHero {
              id: hero
              width: parent.width
              title: root.heroConnection ? root.heroConnection.name : "VPN"
              meta: root.heroMeta
              foreground: root.foreground
              fontFamily: root.fontFamily
              iconOpacity: vpn.connected ? 1.0 : 0.5
              iconComponent: Component {
                Text {
                  text: vpn.connected ? "󰦝" : "󰦞"
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.display
                }
              }
              trailingControl: Component {
                ToggleSwitch {
                  visible: root.heroConnection !== null
                  checked: vpn.connected !== null || vpn.phase !== "idle"
                  busy: vpn.phase === "authenticating" || vpn.phase === "connecting"
                  foreground: hero.foreground
                  onToggled: if (root.heroConnection) vpn.toggle(root.heroConnection.uuid)
                }
              }
            }
          }

          PromptCard {
            id: promptCard
            visible: root.promptOpen
            width: parent.width
          }

          EditorCard {
            id: editor
            visible: root.editing && !root.promptOpen
            width: parent.width
          }

          RowLayout {
            visible: statusLine.text !== "" && !root.promptOpen
            width: parent.width
            spacing: Style.space(8)

            Text {
              id: statusLine
              textFormat: Text.PlainText
              Layout.fillWidth: true
              text: vpn.lastError !== "" ? vpn.lastError : vpn.statusText
              color: vpn.lastError !== "" ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Button {
              visible: vpn.phase === "browser" && vpn.authUrl !== ""
              text: "Open sign-in page"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: vpn.openAuthUrl()
            }

            Button {
              visible: vpn.phase === "authenticating" || vpn.phase === "browser"
              text: "Cancel"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: vpn.cancel()
            }
          }

          PanelSeparator {
            visible: rows.visible
            foreground: root.foreground
          }

          Column {
            id: rows
            visible: !root.editing && !root.promptOpen
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: "CONNECTIONS"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Repeater {
              model: vpn.connections
              ConnectionRow {
                required property var modelData
                required property int index
                width: rows.width
                conn: modelData
                rowIndex: index
              }
            }

            AddRow {
              width: rows.width
            }
          }

        }
      }
    }
  }

  // Server-driven login step: username, password, SMS / MFA code, group
  // choice or certificate trust. Enter submits, Esc cancels the login.
  component PromptCard: Column {
    id: card
    readonly property bool isCert: root.prompt ? root.prompt.kind === "cert" : false
    readonly property var choices: root.prompt && root.prompt.choices ? root.prompt.choices : []
    readonly property bool fieldFocused: field.activeFocus
    spacing: Style.space(8)

    property bool remember: false

    function submit() {
      if (field.text.length === 0) return
      var value = field.text
      field.text = ""
      vpn.answer(value, root.prompt && root.prompt.canRemember && card.remember)
    }

    Text {
      textFormat: Text.PlainText
      visible: text !== ""
      width: parent.width
      text: card.isCert
        ? "The gateway's certificate isn't signed by a trusted authority. Trust it for this connection?"
        : (root.prompt ? root.prompt.message : "")
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
      wrapMode: Text.WordWrap
    }

    Text {
      textFormat: Text.PlainText
      visible: card.isCert && root.prompt && root.prompt.pin !== ""
      width: parent.width
      text: root.prompt ? root.prompt.pin : ""
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WrapAnywhere
    }

    Text {
      textFormat: Text.PlainText
      visible: !card.isCert
      text: root.prompt ? root.prompt.label : ""
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }

    Row {
      visible: card.choices.length > 0
      spacing: Style.space(6)
      Repeater {
        model: card.choices
        Button {
          required property var modelData
          text: modelData
          bordered: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: vpn.answer(modelData)
        }
      }
    }

    RowLayout {
      visible: !card.isCert
      width: parent.width
      spacing: Style.space(6)

      TextField {
        id: field
        Layout.fillWidth: true
        password: root.prompt ? root.prompt.secret === true : false
        placeholderText: root.prompt ? root.prompt.label : ""
        foreground: root.foreground
        font.family: root.fontFamily
        horizontalPadding: Style.spacing.controlGap
        verticalPadding: Style.spacing.controlPaddingY
        inputMethodHints: password ? Qt.ImhSensitiveData | Qt.ImhNoPredictiveText : Qt.ImhNone
        onAccepted: card.submit()
        Keys.onEscapePressed: vpn.cancel()
      }

      PanelActionButton {
        iconText: "󰄬"
        tooltipText: "Submit"
        enabled: field.text.length > 0
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: card.submit()
      }
    }

    Toggle {
      visible: root.prompt ? root.prompt.canRemember === true : false
      width: parent.width
      label: "Remember password"
      description: "Stored in your keyring (Secret Service)"
      checked: card.remember
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: card.remember = !card.remember
    }

    Row {
      visible: card.isCert
      spacing: Style.space(6)
      Button {
        text: "Trust"
        bordered: true
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: vpn.answer("yes")
      }
      Button {
        text: "Cancel"
        bordered: true
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: vpn.answer("no")
      }
    }

    // Each new prompt gets a fresh field, prefilled with the remembered
    // username where the server asks for one.
    Connections {
      target: root
      function onPromptChanged() {
        if (!root.prompt) return
        field.text = root.prompt.value || ""
        card.remember = root.prompt.remember === true
        if (root.prompt.kind !== "cert") Qt.callLater(function() { field.forceActiveFocus(); field.selectAll() })
        else Qt.callLater(function() { keyCatcher.forceActiveFocus() })
      }
    }
  }

  component ConnectionRow: CursorSurface {
    id: row
    property var conn: null
    property int rowIndex: 0
    readonly property bool isActive: conn && conn.state === "activated"
    readonly property bool isWorking: conn && vpn.phase !== "idle" && vpn.activeUuid === conn.uuid
    readonly property string detail: !conn ? "" : conn.protocol !== "openvpn" ? conn.gateway
      : (conn.gateway ? conn.gateway + " · " : "") + (conn.sso ? "OpenVPN SSO" : "OpenVPN")

    hasCursor: root.cursorActive && root.rowIndex === rowIndex
    foreground: root.foreground
    implicitHeight: rowContent.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onEntered: { root.cursorActive = true; root.rowIndex = row.rowIndex }
      onClicked: root.activateRow(row.rowIndex)
    }

    RowLayout {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Text {
        text: row.isActive ? "󰦝" : "󰦞"
        color: root.foreground
        opacity: row.isActive ? 1.0 : 0.6
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon
      }

      ColumnLayout {
        id: rowContent
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: row.conn ? row.conn.name : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: row.isWorking ? "Connecting…" : (row.isActive ? "Connected" : row.detail)
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      Text {
        visible: row.conn ? row.conn.rememberPassword === true : false
        text: "󰌾"
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption

        PanelToolTip {
          visible: lockMouse.containsMouse
          text: "Password saved in keyring"
          fontFamily: root.fontFamily
        }
        MouseArea { id: lockMouse; anchors.fill: parent; hoverEnabled: true }
      }

      PanelActionButton {
        iconText: "󰏫"
        tooltipText: "Edit"
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: if (row.conn) root.startEdit(row.conn.uuid)
      }
    }
  }

  component AddRow: CursorSurface {
    id: addRow
    hasCursor: root.cursorActive && root.rowIndex === vpn.connections.length
    foreground: root.foreground
    implicitHeight: addContent.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onEntered: { root.cursorActive = true; root.rowIndex = vpn.connections.length }
      onClicked: root.startEdit("")
    }

    RowLayout {
      id: addContent
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Text {
        text: "󰐕"
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon
      }
      Text {
        Layout.fillWidth: true
        text: vpn.connections.length === 0 ? "Add your first VPN connection" : "Add connection"
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }
    }
  }

  // Create / edit an OpenConnect profile. The password is only sent when
  // typed; leaving it blank keeps whatever is already in the keyring.
  component EditorCard: Column {
    id: form
    property bool confirmDelete: false
    property bool hasSavedPassword: false
    property bool remember: false
    property string protocol: "anyconnect"
    property bool sso: false
    property bool hip: true
    property string reportedOs: ""
    property string gpTarget: ""
    property bool splitTunnel: false
    property string gateway: ""
    readonly property bool isOpenvpn: protocol === "openvpn"
    readonly property bool isNew: root.editUuid === ""
    // OpenVPN picks its backend by sign-in at import time (NetworkManager or
    // OpenVPN 3), so an existing OpenVPN profile can't switch sign-in.
    readonly property bool ssoCapable: protocol === "anyconnect" || protocol === "gp" || protocol === "fortinet"
      || (isOpenvpn && isNew)
    readonly property bool useSso: sso && (ssoCapable || isOpenvpn)
    readonly property bool isGp: protocol === "gp"
    readonly property string missingBackend: !isOpenvpn ? ""
      : (useSso ? (vpn.openvpn.openvpn3 ? "" : "Browser SSO for OpenVPN needs OpenVPN 3: omarchy pkg aur add openvpn3")
                : (vpn.openvpn.nm ? "" : "OpenVPN needs NetworkManager's plugin: omarchy pkg add networkmanager-openvpn"))
    readonly property bool valid: nameField.text.trim() !== "" && missingBackend === ""
      && (isOpenvpn ? (!isNew || fileField.text.trim() !== "") : gatewayField.text.trim() !== "")
    readonly property var protocolOptions: {
      var openconnect = [
        { value: "anyconnect", label: "Cisco AnyConnect / ocserv" },
        { value: "gp", label: "Palo Alto GlobalProtect" },
        { value: "nc", label: "Juniper Network Connect" },
        { value: "pulse", label: "Pulse / Ivanti Secure" },
        { value: "f5", label: "F5 BIG-IP" },
        { value: "fortinet", label: "Fortinet FortiGate" },
        { value: "array", label: "Array Networks" }
      ]
      var openvpn = { value: "openvpn", label: "OpenVPN (.ovpn file)" }
      if (isNew) return openconnect.concat([openvpn])
      return isOpenvpn ? [openvpn] : openconnect
    }

    // A file chosen in the portal dialog; names the connection when it has no name yet.
    function setFile(path) {
      fileField.text = path
      if (nameField.text.trim() === "")
        nameField.text = path.replace(/^.*\//, "").replace(/\.(ovpn|conf)$/i, "")
    }
    spacing: Style.space(8)

    function load(conn) {
      confirmDelete = false
      nameField.text = conn ? conn.name : ""
      gatewayField.text = conn ? conn.gateway : ""
      gateway = conn ? (conn.gateway || "") : ""
      fileField.text = ""
      protocol = conn ? (conn.protocol || "anyconnect") : "anyconnect"
      groupField.text = conn ? (conn.usergroup || "") : ""
      sso = conn ? conn.sso === true : false
      hip = conn ? conn.hip === true : true
      reportedOs = conn ? (conn.reportedOs || "") : ""
      gpTarget = conn && String(conn.usergroup || "").indexOf("gateway") === 0 ? "gateway" : ""
      splitTunnel = conn ? conn.splitTunnel === true : false
      userField.text = conn ? (conn.username || "") : ""
      passwordField.text = ""
      hasSavedPassword = conn ? conn.rememberPassword === true : false
      remember = hasSavedPassword
      Qt.callLater(function() { nameField.focusInput() })
    }

    function submit() {
      if (!valid || vpn.saving) return
      var profile = {
        uuid: root.editUuid,
        name: nameField.text.trim(),
        gateway: form.isOpenvpn ? "" : gatewayField.text.trim(),
        ovpnFile: form.isOpenvpn && form.isNew ? fileField.text.trim() : "",
        protocol: form.protocol,
        usergroup: form.isOpenvpn ? "" : (form.isGp ? form.gpTarget : groupField.text.trim()),
        username: form.useSso ? "" : userField.text.trim(),
        password: form.remember && !form.useSso ? passwordField.text : "",
        rememberPassword: form.remember && !form.useSso,
        sso: form.useSso,
        hip: form.isGp && form.hip,
        reportedOs: form.reportedOs,
        splitTunnel: form.splitTunnel
      }
      passwordField.text = ""
      vpn.save(profile)
    }

    PanelSectionHeader {
      text: form.isNew ? "NEW CONNECTION" : "EDIT CONNECTION"
      foreground: root.foreground
      fontFamily: root.fontFamily
    }

    FormField { id: nameField; label: "Name"; placeholder: "Work VPN"; next: form.isOpenvpn ? null : gatewayField }
    FormField {
      id: gatewayField
      visible: !form.isOpenvpn
      label: form.isGp ? "Portal" : (form.protocol === "fortinet" ? "Gateway (host or host:port)" : "Gateway")
      placeholder: form.protocol === "fortinet" ? "vpn.example.com:10443" : "vpn.example.com"
      next: groupField.visible ? groupField : null
    }

    FormLabel { text: "Protocol" }
    Dropdown {
      width: parent.width
      showLabel: false
      value: form.protocol
      fontFamily: root.fontFamily
      options: form.protocolOptions
      onChanged: function(value) { form.protocol = value }
    }

    // OpenVPN: the provider's .ovpn file is imported once.
    FormLabel { visible: form.isOpenvpn && form.isNew; text: "Configuration file (.ovpn)" }
    RowLayout {
      visible: form.isOpenvpn && form.isNew
      width: parent.width
      spacing: Style.space(6)

      TextField {
        id: fileField
        Layout.fillWidth: true
        placeholderText: "~/Downloads/work.ovpn"
        foreground: root.foreground
        font.family: root.fontFamily
        horizontalPadding: Style.spacing.controlGap
        verticalPadding: Style.spacing.controlPaddingY
        onAccepted: form.submit()
        Keys.onEscapePressed: root.stopEdit()
      }

      Button {
        text: "Browse…"
        bordered: true
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: vpn.pickFile()
      }
    }

    Text {
      visible: form.isOpenvpn && !form.isNew
      width: parent.width
      text: (form.gateway ? "Server " + form.gateway + " · " : "")
        + (form.sso ? "Browser SSO via OpenVPN 3" : "Password / certificate via NetworkManager")
        + ". To change the file or sign-in, delete the connection and import it again."
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }

    FormLabel { visible: form.ssoCapable; text: "Sign-in" }
    Dropdown {
      visible: form.ssoCapable
      width: parent.width
      showLabel: false
      value: form.sso ? "sso" : "password"
      fontFamily: root.fontFamily
      options: form.isOpenvpn
        ? [
          { value: "password", label: "Username & password / certificate (+ code)" },
          { value: "sso", label: "Browser SSO / SAML (OpenVPN 3)" }
        ]
        : [
          { value: "password", label: "Username & password (+ code / token)" },
          { value: "sso", label: "Browser SSO (Microsoft, Okta, Google…)" }
        ]
      onChanged: function(value) { form.sso = value === "sso" }
    }

    Text {
      visible: form.missingBackend !== ""
      width: parent.width
      text: form.missingBackend
      color: root.urgent
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }

    Text {
      visible: form.useSso
      width: parent.width
      text: form.isOpenvpn
        ? "OpenVPN 3 opens the sign-in page in your default browser (OpenVPN Access Server, CloudConnexa and other servers using OpenVPN web authentication)."
        : form.isGp
        ? "Signs in through your default browser via gpauth."
        : (form.protocol === "fortinet"
          ? "Opens the FortiGate SSO page in your default browser; it hands back to 127.0.0.1:8020."
          : "Opens the gateway's SSO page in your default browser.")
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }

    // GlobalProtect: portal vs direct gateway, HIP report and reported OS.
    FormLabel { visible: form.isGp; text: "Connect to" }
    Dropdown {
      visible: form.isGp
      width: parent.width
      showLabel: false
      value: form.gpTarget === "gateway" ? "gateway" : "portal"
      fontFamily: root.fontFamily
      options: [
        { value: "portal", label: "Portal (pick a gateway at login)" },
        { value: "gateway", label: "Gateway directly" }
      ]
      onChanged: function(value) { form.gpTarget = value === "gateway" ? "gateway" : "" }
    }

    FormLabel { visible: form.isGp; text: "Report OS as" }
    Dropdown {
      visible: form.isGp
      width: parent.width
      showLabel: false
      value: form.reportedOs === "" ? "default" : form.reportedOs
      fontFamily: root.fontFamily
      options: [
        { value: "default", label: "Linux (default)" },
        { value: "win", label: "Windows" },
        { value: "mac-intel", label: "macOS" }
      ]
      onChanged: function(value) { form.reportedOs = value === "default" ? "" : value }
    }

    Toggle {
      visible: form.isGp
      width: parent.width
      label: "Send HIP report"
      description: "Host-integrity check many GlobalProtect gateways require"
      checked: form.hip
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: form.hip = !form.hip
    }

    Toggle {
      visible: !(form.isOpenvpn && form.useSso)
      width: parent.width
      label: "Split tunnel"
      description: "Only company networks and names go through the VPN; internet and DNS stay on your connection"
      checked: form.splitTunnel
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: form.splitTunnel = !form.splitTunnel
    }

    FormField {
      id: groupField
      visible: !form.isGp && !form.isOpenvpn
      label: form.protocol === "fortinet" ? "Realm (optional)" : "Group (optional)"
      placeholder: form.protocol === "fortinet" ? "Leave empty for the default realm" : "Leave empty to pick at login"
      next: userField.visible ? userField : null
    }
    FormField {
      id: userField
      visible: !form.useSso
      label: "Username (optional)"
      placeholder: form.isOpenvpn ? "Asked at login when the server needs one" : "Asked at login when empty"
      next: form.remember ? passwordField : null
    }

    Toggle {
      visible: !form.useSso
      width: parent.width
      label: "Remember password"
      description: form.remember && form.hasSavedPassword && passwordField.text === ""
        ? "Saved in your keyring — type to replace"
        : "Stored in your keyring (Secret Service), never in a file"
      checked: form.remember
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: form.remember = !form.remember
    }

    FormField {
      id: passwordField
      visible: form.remember && !form.useSso
      label: "Password"
      password: true
      placeholder: form.hasSavedPassword ? "••••••••  (unchanged)" : "Password"
    }

    Text {
      width: parent.width
      visible: !form.useSso
      text: "SMS / MFA / token codes are always asked for at login — they're never stored."
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }

    Row {
      spacing: Style.space(6)
      Button {
        text: vpn.saving ? "Saving…" : "Save"
        bordered: true
        enabled: form.valid && !vpn.saving
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: form.submit()
      }
      Button {
        text: "Cancel"
        bordered: true
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.stopEdit()
      }
      Button {
        visible: !form.isNew
        text: form.confirmDelete ? "Really delete?" : "Delete"
        bordered: true
        foreground: form.confirmDelete ? root.urgent : root.foreground
        fontFamily: root.fontFamily
        onClicked: {
          if (!form.confirmDelete) { form.confirmDelete = true; return }
          vpn.deleteConnection(root.editUuid)
          root.stopEdit()
        }
      }
    }
  }

  component FormLabel: Text {
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
  }

  component FormField: Column {
    id: ff
    property string label: ""
    property string placeholder: ""
    property bool password: false
    property Item next: null
    property alias text: input.text
    function focusInput() { input.forceActiveFocus() }
    width: parent ? parent.width : 0
    spacing: Style.space(3)

    Text {
      text: ff.label
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
    TextField {
      id: input
      width: parent.width
      password: ff.password
      placeholderText: ff.placeholder
      foreground: root.foreground
      font.family: root.fontFamily
      horizontalPadding: Style.spacing.controlGap
      verticalPadding: Style.spacing.controlPaddingY
      onAccepted: ff.next ? ff.next.focusInput() : editor.submit()
      Keys.onEscapePressed: root.stopEdit()
    }
  }
}
