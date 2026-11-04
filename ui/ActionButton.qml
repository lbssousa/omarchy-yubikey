import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui as Ui

Ui.Button {
  id: root
  property bool primary: false
  focusable: true
  bordered: !primary
  horizontalPadding: Style.space(14)
  verticalPadding: Style.space(9)
  foreground: primary ? Commons.Color.background : Commons.Color.foreground
  background: primary ? Commons.Color.accent : "transparent"
  accent: primary ? Commons.Color.foreground : Commons.Color.accent
  opacity: enabled ? 1 : 0.42
  Accessible.role: Accessible.Button
  Accessible.name: text
  Accessible.onPressAction: if (enabled) root.clicked()
}
