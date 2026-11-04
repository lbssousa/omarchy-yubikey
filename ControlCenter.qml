import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "ui" as Setup
import "ui/ControlModel.js" as Model

Item {
  id: root
  property var shell: null
  property var manifest: null
  property bool opened: false
  readonly property string backend: decodeURIComponent(Qt.resolvedUrl("scripts/control-center.py").toString().replace(/^file:\/\//, ""))
  function open(payloadJson) { opened = true; refresh(); Qt.callLater(function() { panelContent.focusFirst() }) }
  function close() { opened = false }
  function dismiss() {
    opened = false
    if (shell && typeof shell.hide === "function") shell.hide((manifest && manifest.id) || "yubikey.setup")
  }
  function toggle() { if (opened) dismiss(); else open("{}") }
  function refresh() { if (opened && !statusProcess.running) statusProcess.running = true }
  Process {
    id: statusProcess
    command: ["python3", root.backend, "status"]
    stdout: StdioCollector {
      onStreamFinished: {
        var value = null
        try { value = Model.cleanSnapshot(JSON.parse(text)) } catch (error) {}
        if (value) {
          panelContent.snapshot = value
          if (value.operation.phase === "failed" || value.operation.phase === "interrupted") {
            panelContent.showNotice("The previous operation stopped. Review its terminal output and recovery instructions.", true)
          }
        } else { panelContent.showNotice("Could not read setup status. Check that Python 3 is installed, then refresh.", true) }
      }
    }
    stderr: StdioCollector { }
  }
  Process {
    id: launchProcess
    stdout: StdioCollector {
      onStreamFinished: {
        var ok = false
        try { ok = JSON.parse(text).ok === true } catch (error) {}
        panelContent.showNotice(ok ? "Continue in the terminal, then return here to check status." : "Could not open this operation. Check prerequisites or another open setup terminal.", !ok)
      }
    }
    stderr: StdioCollector { }
    onExited: root.refresh()
  }
  Timer { interval: 5000; repeat: true; running: root.opened; onTriggered: root.refresh() }
  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "omarchy-yubikey-setup"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    Rectangle { anchors.fill: parent; color: Commons.Color.menu.scrim }
    MouseArea { anchors.fill: parent; onClicked: root.dismiss() }
    BorderSurface {
      width: Math.min(Style.space(1020), panel.width - Style.space(32))
      height: Math.min(Style.space(760), panel.height - Style.space(32))
      anchors.centerIn: parent
      color: Commons.Color.menu.background
      borderSpec: Border.surfaceSpec("menu", "border", Commons.Color.menu.border, Math.max(1, Style.space(1)))
      radius: Style.cornerRadius
      padding: 0
      MouseArea { anchors.fill: parent; onClicked: {} }
      Setup.ControlPanel {
        id: panelContent
        anchors.fill: parent
        anchors.margins: Style.space(1)
        refreshing: statusProcess.running
        launching: launchProcess.running
        onRefreshRequested: root.refresh()
        onCloseRequested: root.dismiss()
        onOperationRequested: function(action, parameters) {
          if (launchProcess.running || Model.actions.indexOf(action) < 0) return
          launchProcess.command = ["python3", root.backend, "launch", action].concat(parameters)
          launchProcess.running = true
        }
        onGuideRequested: function(name) {
          if (["control-center", "install", "luks", "enrollment-sync"].indexOf(name) >= 0)
            Qt.openUrlExternally("https://github.com/marselnenaj/omarchy-yubikey/blob/main/docs/" + name + ".md")
        }
      }
    }
  }
}
