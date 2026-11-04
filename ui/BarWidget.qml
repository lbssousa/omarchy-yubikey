import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

BarIconButton {
  property string moduleName: ""
  property var settings: ({})
  text: "󰌆"
  tooltipText: "Omarchy YubiKey"
  onPressed: function(button) {
    if (button === Qt.LeftButton)
      Quickshell.execDetached(["omarchy-shell", "shell", "summon", "yubikey.setup", "{}"])
  }
}
