import QtQuick
import QtTest
TestCase {
  name: "ControlPanel"
  property var panel
  property int emitted: 0
  property var lastParameters
  when: false
  function test_actions_and_keyboard() {
    var originalSnapshot = panel.snapshot
    verify(panel.width > 0)
    var translations = findChild(panel, "setupTranslations")
    verify(translations !== null)
    compare(typeof translations.number, "function")
    compare(translations.number(12).length, 2)
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
    panel.page = 1
    wait(30)
    function checkPublicFields(item) {
      if (item.readOnly === true && item.selectByMouse === true && item.visible) {
        var point = item.mapToItem(panel, 0, 0)
        verify(point.x >= -1 && point.x + item.width <= panel.width + 1, "Public identity field must fit horizontally")
        verify(item.contentWidth <= item.width + 1, "Long fingerprints must wrap within the field")
      }
      if (item.children) for (var i=0;i<item.children.length;i++) checkPublicFields(item.children[i])
    }
    checkPublicFields(panel)
    var openpgpCard = findChild(panel,"openpgpCard")
    verify(openpgpCard.visible)
    var openpgpImport = findChild(panel,"openpgpImport")
    var openpgpRemove = findChild(panel,"openpgpRemove")
    function openpgpAction(button) {
      button.clicked()
      var action = panel.pendingAction
      keyClick(Qt.Key_Escape)
      compare(dialog.opened,false)
      return action
    }
    // Ready key: the import button offers an update, not highlighted; removal is separate.
    var updateText = openpgpImport.text
    verify(!openpgpImport.primary)
    compare(openpgpAction(openpgpImport), "openpgp-import")
    verify(openpgpRemove.enabled)
    compare(openpgpAction(openpgpRemove), "openpgp-remove")
    var savedOpenpgp = panel.snapshot.openpgp
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:false,linked:false,trusted:false,ready:false,key:null}})
    verify(openpgpImport.text !== updateText)
    verify(openpgpImport.primary)
    verify(!openpgpRemove.enabled)
    compare(openpgpAction(openpgpImport), "openpgp-import")
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:false,trusted:true,ready:false,key:{algorithm:"ed25519"}}})
    compare(openpgpImport.text, updateText)
    verify(openpgpImport.primary)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:true,ready:true,key:{algorithm:"ed25519",expired:true}}})
    verify(openpgpImport.primary)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:savedOpenpgp})
    var details = findChild(panel,"openpgpDetails")
    verify(details.visible)
    compare(panel.openpgpDetails().length, 9)
    verify(openpgpCard.ready)
    var identityToggle = findChild(panel,"openpgpIdentityToggle")
    verify(identityToggle.visible)
    identityToggle.clicked()
    compare(panel.openpgpDetails().length, 10)
    identityToggle.clicked()
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:true,key:{algorithm:"ed25519",sign:true,encrypt:true,authenticate:false,expires:"2020-01-01",expired:true,uids:1}}})
    verify(!openpgpCard.ready)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,ready:true,key:{algorithm:"ed25519",revoked:true}}})
    verify(!openpgpCard.ready)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:false,key:null}})
    verify(!details.visible)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:false,imported:false,linked:false,trusted:false,key:null}})
    verify(!openpgpCard.visible)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:false,key:{algorithm:"ed25519",sign:true,encrypt:true,authenticate:true,expires:"2030-01-01",expired:false,uids:2}}})
    var sshCard = findChild(panel,"sshCard")
    verify(sshCard.visible)
    verify(findChild(panel,"sshKeys").visible)
    compare(panel.sshKeyTitle({application:"ssh:github.com", user:"work"}), "ssh:github.com · work")
    compare(panel.sshKeyTitle({application:"ssh:github.com", user:""}), "ssh:github.com")
    compare(panel.sshKeyTitle({application:"ssh:", user:"0102030405060708090a0b0c0d0e0f10"}), "ssh: · 0102030405060708…")
    var remove = findChild(panel,"sshRemove0")
    verify(remove !== null)
    remove.clicked()
    verify(dialog.opened)
    compare(panel.pendingAction,"ssh-remove")
    verify(dialog.message.indexOf(findChild(panel,"sshDeleteWarning").text) >= 0, "Removal offers permanent deletion, so it carries the warning")
    keyClick(Qt.Key_Right)
    keyClick(Qt.Key_Return)
    compare(dialog.opened,false)
    compare(lastParameters.length,2)
    compare(lastParameters[0],"--key-id")
    compare(lastParameters[1],"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    var create = findChild(panel,"sshCreate")
    verify(create.visible && create.enabled)
    create.clicked()
    verify(dialog.opened)
    compare(panel.pendingAction,"ssh-create")
    keyClick(Qt.Key_Right)
    keyClick(Qt.Key_Return)
    compare(dialog.opened,false)
    compare(lastParameters.length,0)
    var warning = findChild(panel,"sshDeleteWarning")
    verify(warning.visible)
    verify(warning.text.length > 0)
    var deleteToken = findChild(panel,"sshDeleteToken")
    verify(deleteToken.visible && deleteToken.enabled)
    deleteToken.clicked()
    verify(dialog.opened)
    compare(panel.pendingAction,"ssh-delete-token")
    verify(dialog.message.indexOf(warning.text) >= 0, "The confirmation must repeat the permanent-deletion warning")
    keyClick(Qt.Key_Escape)
    compare(dialog.opened,false)
    create.clicked()
    verify(dialog.message.indexOf(warning.text) < 0, "Other actions do not carry the deletion warning")
    keyClick(Qt.Key_Escape)
    panel.page = 0
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
    panel.snapshot = originalSnapshot
  }
}
