import QtQuick
import Quickshell
import Quickshell.Io

Item {
  id: root

  property var settings: ({})

  property var connections: []
  // idle | authenticating | browser | prompt | connecting
  property string phase: "idle"
  property string activeUuid: ""
  property var prompt: null
  property string statusText: ""
  property string lastError: ""

  readonly property string helperPath: Qt.resolvedUrl("helper.py").toString().replace(/^file:\/\//, "")
  readonly property bool busy: phase !== "idle" || controlProcess.running
  readonly property bool saving: saveProcess.running
  readonly property var connected: {
    for (var i = 0; i < connections.length; i++) {
      if (connections[i].state === "activated") return connections[i]
    }
    return null
  }
  readonly property int refreshIntervalSec: Math.max(3, parseInt(settings && settings.refreshIntervalSec) || 10)

  function refresh() {
    if (listProcess.running) return
    listProcess.running = true
  }

  function connectionByUuid(uuid) {
    for (var i = 0; i < connections.length; i++) {
      if (connections[i].uuid === uuid) return connections[i]
    }
    return null
  }

  function connect(uuid) {
    if (connectProcess.running || !uuid) return
    lastError = ""
    prompt = null
    activeUuid = uuid
    phase = "authenticating"
    statusText = "Contacting gateway…"
    connectProcess.command = ["python3", helperPath, "connect", uuid]
    connectProcess.running = true
  }

  function answer(text, remember) {
    if (!connectProcess.running || phase !== "prompt") return
    connectProcess.write(JSON.stringify({ answer: String(text), remember: remember === true }) + "\n")
    prompt = null
    phase = "authenticating"
    statusText = "Verifying…"
  }

  function cancel() {
    if (!connectProcess.running) return
    if (phase === "prompt") connectProcess.write(JSON.stringify({ cancel: true }) + "\n")
    else connectProcess.signal(15)
  }

  function disconnect(uuid) {
    if (controlProcess.running || !uuid) return
    lastError = ""
    statusText = "Disconnecting…"
    controlProcess.command = ["python3", helperPath, "disconnect", uuid]
    controlProcess.running = true
  }

  signal saved(string uuid)

  // profile: { uuid?, name, gateway, protocol, usergroup, username, password, rememberPassword }
  // Sent over stdin so the password never shows up in argv / ps.
  function save(profile) {
    if (saveProcess.running) return
    lastError = ""
    saveProcess.payload = JSON.stringify(profile)
    saveProcess.command = ["python3", helperPath, "save"]
    saveProcess.running = true
  }

  function deleteConnection(uuid) {
    if (controlProcess.running || !uuid) return
    lastError = ""
    statusText = "Deleting…"
    controlProcess.command = ["python3", helperPath, "delete", uuid]
    controlProcess.running = true
  }

  function toggle(uuid) {
    var conn = connectionByUuid(uuid)
    if (!conn) return
    if (phase !== "idle" && activeUuid === uuid) cancel()
    else if (conn.state === "activated" || conn.state === "activating") disconnect(uuid)
    else connect(uuid)
  }

  function handleEvent(line) {
    var ev
    try { ev = JSON.parse(line) } catch (e) { return }
    if (ev.event === "prompt") {
      prompt = ev
      phase = "prompt"
      statusText = ""
    } else if (ev.event === "state") {
      if (ev.state === "authenticating") { phase = "authenticating"; statusText = "Contacting gateway…" }
      else if (ev.state === "browser") { phase = "browser"; statusText = "Finish signing in in your browser…" }
      else if (ev.state === "connecting") { phase = "connecting"; statusText = "Bringing up tunnel…" }
      else if (ev.state === "connected") statusText = ""
    } else if (ev.event === "log") {
      if (phase === "authenticating") statusText = ev.text
    } else if (ev.event === "error") {
      lastError = ev.text
    }
  }

  Process {
    id: listProcess
    command: ["python3", root.helperPath, "list"]
    stdout: StdioCollector {
      onStreamFinished: {
        try {
          var parsed = JSON.parse(text)
          root.connections = parsed.connections || []
          if (!parsed.ok && parsed.error) root.lastError = parsed.error
        } catch (e) {
          root.lastError = "Could not read VPN connections"
        }
      }
    }
  }

  Process {
    id: connectProcess
    stdinEnabled: true
    stdout: SplitParser { onRead: function(data) { root.handleEvent(data) } }
    onExited: function(exitCode) {
      root.phase = "idle"
      root.prompt = null
      root.statusText = ""
      root.refresh()
    }
  }

  Process {
    id: saveProcess
    property string payload: ""
    stdinEnabled: true
    onStarted: {
      write(payload + "\n")
      payload = ""
    }
    stdout: SplitParser {
      onRead: function(data) {
        var ev
        try { ev = JSON.parse(data) } catch (e) { return }
        if (ev.event === "error") root.lastError = ev.text
        else if (ev.event === "saved") root.saved(ev.uuid)
      }
    }
    onExited: root.refresh()
  }

  Process {
    id: controlProcess
    stderr: StdioCollector { id: controlStderr }
    onExited: function(exitCode) {
      root.statusText = ""
      if (exitCode !== 0) root.lastError = String(controlStderr.text || "Command failed").trim()
      root.refresh()
    }
  }

  Timer {
    interval: root.refreshIntervalSec * 1000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }
}
