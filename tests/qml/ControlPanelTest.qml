import QtQuick
import QtTest
TestCase {
  name: "ControlPanel"
  property var panel
  property int emitted: 0
  property var lastParameters
  when: false
  function test_actions_and_keyboard() {
    verify(panel.width > 0)
    function checkTabs(item) {
      if (item.objectName === "sidebarTab" && !panel.compact)
        verify(item.implicitWidth <= item.width, "Navigation label must fit its button")
      if (item.children) for (var i=0;i<item.children.length;i++) checkTabs(item.children[i])
    }
    checkTabs(panel)
    panel.operationRequested.connect(function(action, parameters) { emitted++; lastParameters=parameters })
    panel.ask("setup-sudo", "Configure sudo")
    var dialog = findChild(panel,"actionConfirmation")
    verify(dialog.opened)
    compare(dialog.selectedIndex,0)
    keyClick(Qt.Key_Return)
    compare(dialog.opened,false)
    compare(emitted,0)
    panel.ask("luks-enroll", "Enroll disk key", "/dev/example")
    keyClick(Qt.Key_Right)
    keyClick(Qt.Key_Return)
    compare(emitted,1)
    compare(lastParameters[0],"--device")
    compare(lastParameters[1],"/dev/example")
    panel.ask("rollback","Restore","","../../bad")
    compare(dialog.opened,false)
    panel.ask("setup", "Guided setup")
    keyClick(Qt.Key_Escape)
    compare(dialog.opened,false)
    var closed = 0
    panel.closeRequested.connect(function() { closed++ })
    panel.focusFirst()
    keyClick(Qt.Key_Escape)
    compare(closed,1)
    panel.snapshot = Object.assign({}, panel.snapshot, {operation:{phase:"running"}})
    panel.ask("setup", "Guided setup")
    compare(dialog.opened,false)
    panel.snapshot = Object.assign({}, panel.snapshot, {operation:{}})
    panel.notice = ""
    panel.failed = false
    for (var page=0;page<5;page++) {
      panel.page=page; wait(30); verify(panel.height>0)
      var scroll = findChild(panel,"contentScroll")
      if (scroll.contentHeight > scroll.availableHeight) {
        scroll.contentItem.contentY = scroll.contentHeight - scroll.availableHeight
        verify(scroll.contentItem.contentY > 0)
        scroll.contentItem.contentY = 0
      }
    }
  }
}
