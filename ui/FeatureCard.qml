import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

Rectangle {
  id: root
  property string title: ""
  property string description: ""
  property string badge: ""
  property bool ready: false
  default property alias actions: actionFlow.data
  readonly property real padding: Style.space(18)
  Layout.fillWidth: true
  implicitHeight: content.implicitHeight + padding * 2
  color: Util.alpha(Commons.Color.foreground, 0.025)
  border.color: Util.alpha(Commons.Color.foreground, 0.13)
  border.width: 1
  radius: Style.cornerRadius
  ColumnLayout {
    id: content
    anchors { left: parent.left; right: parent.right; top: parent.top; margins: root.padding }
    spacing: Style.space(10)
    RowLayout {
      Layout.fillWidth: true
      Text {
        Layout.fillWidth: true
        text: root.title
        textFormat: Text.PlainText
        color: Commons.Color.foreground
        font { family: Style.font.family; pixelSize: Style.font.title; bold: true }
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      }
      Rectangle {
        visible: root.badge !== ""
        implicitWidth: badgeText.implicitWidth + Style.space(16)
        implicitHeight: badgeText.implicitHeight + Style.space(8)
        color: Util.alpha(root.ready ? Commons.Color.accent : Commons.Color.foreground, 0.09)
        radius: Style.cornerRadius
        Text {
          id: badgeText
          anchors.centerIn: parent
          text: root.badge
          textFormat: Text.PlainText
          color: root.ready ? Commons.Color.accent : Commons.Color.muted
          font { family: Style.font.family; pixelSize: Style.font.caption }
        }
      }
    }
    Text {
      Layout.fillWidth: true
      visible: root.description !== ""
      text: root.description
      textFormat: Text.PlainText
      color: Util.alpha(Commons.Color.foreground, 0.73)
      font { family: Style.font.family; pixelSize: Style.font.body }
      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      lineHeight: 1.25
    }
    Flow {
      id: actionFlow
      Layout.fillWidth: true
      Layout.topMargin: children.length ? Style.space(4) : 0
      spacing: Style.space(8)
    }
  }
}
