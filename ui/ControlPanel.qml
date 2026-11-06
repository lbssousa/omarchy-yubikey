import QtQuick
import QtQuick.Controls as QQC
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons
import qs.Ui as Ui
import "ControlModel.js" as Model
import "." as Local

Item {
  id: root
  property var snapshot: null
  property bool refreshing: false
  property bool launching: false
  property string notice: ""
  property bool failed: false
  property int page: 0
  onPageChanged: Qt.callLater(function() { if (scroll.contentItem) scroll.contentItem.contentY = 0 })
  readonly property bool compact: width < Style.space(760)
  readonly property bool busy: launching || !!snapshot && ["starting", "running"].indexOf(snapshot.operation.phase) >= 0
  readonly property bool canAct: !!snapshot && snapshot.supported && !busy
  readonly property int keyCount: snapshot ? snapshot.enrollment.count : 0
  readonly property int sshCount: snapshot && snapshot.ssh ? snapshot.ssh.count : 0
  readonly property var sshKeys: snapshot && snapshot.ssh && snapshot.ssh.keys ? snapshot.ssh.keys : []
  // Public identity only; filenames and credential handles stay in the terminal.
  function sshKeyDetails(key) {
    var parts = [key.type === "ed25519-sk" ? "Ed25519-SK" : key.type === "ecdsa-sk" ? "ECDSA-SK" : strings.t("Other")]
    parts.push(key.passphrase ? strings.t("passphrase") : strings.t("no passphrase"))
    if (key.host) parts.push(strings.t("git host configured"))
    return parts.join(" · ")
  }
  property bool showOpenpgpIdentity: false
  property string pendingAction: ""
  property string pendingTitle: ""
  property var pendingParameters: []
  signal refreshRequested()
  signal operationRequested(string action, var parameters)
  signal closeRequested()
  signal guideRequested(string name)
  Local.Translations { id: strings; objectName: "setupTranslations" }
  LayoutMirroring.enabled: strings.rightToLeft
  LayoutMirroring.childrenInherit: true
  readonly property var pages: [strings.t("Overview"), strings.t("Security keys"), strings.t("Desktop"), strings.t("Keyring"), strings.t("Disk & recovery")]
  readonly property var shortPages: [strings.t("Overview"), strings.t("Keys"), strings.t("Desktop"), strings.t("Keyring"), strings.t("Recovery")]
  readonly property var subtitles: [strings.t("Security-key authentication, in one place."), strings.t("Keep a spare key ready before you need it."), strings.t("Choose how your key works with sudo and your session."), strings.t("Unlock your existing GNOME Keyring with a touch."), strings.t("Enroll disk keys and recover previous PAM settings.")]

  function ask(action, title, device, backup, keyId) {
    if (!root.canAct) return
    var parameters = Model.parameters(action, device, backup, keyId)
    if (parameters === null) { root.notice = strings.t("Check the device path or backup ID."); root.failed = true; return }
    root.pendingAction = action
    root.pendingTitle = title
    root.pendingParameters = parameters
    confirmation.opened = true
    confirmation.selectedIndex = 0
    keyCatcher.forceActiveFocus()
  }
  function policy(value) {
    if (!value || value.state === "not-configured") return strings.t("Not configured")
    if (value.state === "external") return strings.t("Custom configuration")
    if (value.state === "unreadable") return strings.t("Unable to read")
    return value.pin ? strings.t("PIN + touch") : strings.t("Touch only")
  }
  function desktopState() {
    return snapshot && snapshot.plugins.lock.enabled && snapshot.plugins.polkit.enabled ? strings.t("Enabled") : strings.t("Not enabled")
  }
  function helperState() {
    if (!snapshot || !snapshot.keyring.installed) return strings.t("Not installed")
    return snapshot.keyring.state === "enrolled" ? strings.t("Ready") : strings.t("Needs enrollment")
  }
  readonly property var openpgp: snapshot && snapshot.openpgp ? snapshot.openpgp : {card: false, imported: false, linked: false, trusted: false, key: null}
  function openpgpState() {
    if (!openpgp.imported) return strings.t("Not imported")
    if (openpgp.key && openpgp.key.revoked) return strings.t("Revoked")
    if (openpgp.key && openpgp.key.disabled) return strings.t("Disabled")
    if (openpgp.key && openpgp.key.expired) return strings.t("Expired")
    if (openpgp.ready) return strings.t("Ready")
    if (!openpgp.linked) return strings.t("Not linked to the card")
    return strings.t("Unavailable")
  }
  // An imported key that is not ready (unlinked, expired, revoked or disabled)
  // may be fixed by fetching it again, which also refreshes the card links.
  function openpgpNeedsUpdate() {
    var key = openpgp.key || {}
    return openpgp.imported === true && (openpgp.ready !== true || key.expired === true || key.revoked === true || key.disabled === true)
  }
  // Omarchy 4.5's Commons.Translations can shadow the bundled loader and lack
  // number(); fall back to plain digits rather than losing every detail row.
  function openpgpNumber(value) {
    return typeof strings.number === "function" ? strings.number(value) : String(value)
  }
  readonly property var openpgpRows: openpgpDetails()
  function slotState(slot) {
    if (slot.ready) return strings.t("On this card")
    if (slot.location === "disk") return strings.t("Local secret copy")
    if (slot.location === "other-card") return strings.t("Other card")
    return slot.linked ? strings.t("Unavailable") : strings.t("Not linked to the card")
  }
  function openpgpDetails() {
    var key = openpgp.key
    if (!key) return []
    var uses = []
    if (key.sign) uses.push(strings.t("Sign"))
    if (key.encrypt) uses.push(strings.t("Encrypt"))
    if (key.authenticate) uses.push(strings.t("Authenticate"))
    var rows = [
      {label: strings.t("Fingerprint"), value: key.fingerprint || strings.t("Unavailable")},
      {label: strings.t("Algorithm"), value: key.algorithm === "other" ? strings.t("Other") : key.algorithm},
      {label: strings.t("Use"), value: uses.length ? uses.join(", ") : strings.t("None")},
      {label: strings.t("Expires"), value: !key.expires ? strings.t("Never") : key.expired ? strings.t("Expired on %1", [key.expires]) : key.expires},
      {label: strings.t("User IDs"), value: openpgpNumber(key.uids)},
      {label: strings.t("Ownertrust"), value: openpgp.trusted ? strings.t("Ultimate") : strings.t("Not trusted yet")}
    ]
    if (root.showOpenpgpIdentity && key.uid) rows.push({label: strings.t("Name and email"), value: key.uid})
    if (openpgp.local) rows.push({label: strings.t("Local key material"), value: strings.t("Local secret copy")})
    var roles = ["sign", "encrypt", "authenticate"]
    var labels = [strings.t("Sign"), strings.t("Encrypt"), strings.t("Authenticate")]
    roles.forEach(function(role, i) {
      var slot = (openpgp.slots || {})[role]
      if (slot && slot.present) rows.push({label: labels[i], value: root.slotState(slot)})
    })
    return rows
  }
  function showNotice(source, error) { notice = strings.t(source); failed = error }
  Keys.onPressed: function(event) {
    if (confirmation.handleKey(event)) { event.accepted = true; return }
    if (event.key === Qt.Key_Escape) { root.closeRequested(); event.accepted = true }
  }
  function focusFirst() { refreshButton.forceActiveFocus() }

  Rectangle { anchors.fill: parent; color: Commons.Color.menu.background }
  ColumnLayout {
    anchors.fill: parent
    spacing: 0
    RowLayout {
      Layout.fillWidth: true
      Layout.margins: Style.space(22)
      spacing: Style.space(12)
      Rectangle {
        implicitWidth: Style.space(40); implicitHeight: Style.space(40)
        radius: Style.cornerRadius
        color: Util.alpha(Commons.Color.accent, 0.13)
        Text { anchors.centerIn: parent; text: "󰌆"; color: Commons.Color.accent; font { family: Style.font.family; pixelSize: Style.space(23) } }
      }
      Column {
        Layout.fillWidth: true
        spacing: Style.space(3)
        Text { text: "Omarchy YubiKey"; textFormat: Text.PlainText; color: Commons.Color.foreground; font { family: Style.font.family; pixelSize: Style.font.title; bold: true } }
        Text { text: strings.t("SETUP & MANAGEMENT"); color: Commons.Color.muted; font { family: Style.font.family; pixelSize: Style.font.caption; letterSpacing: 1 } }
      }
      ActionButton { id: refreshButton; text: root.refreshing ? strings.t("Checking…") : strings.t("Refresh"); enabled: !root.refreshing; onClicked: root.refreshRequested() }
      Ui.Button {
        text: "×"; focusable: true; fontSize: Style.space(25)
        tooltipText: strings.t("Close")
        Accessible.role: Accessible.Button; Accessible.name: strings.t("Close")
        onClicked: root.closeRequested()
      }
    }
    Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: Util.alpha(Commons.Color.foreground, 0.13) }
    RowLayout {
      Layout.fillWidth: true; Layout.fillHeight: true; spacing: 0
      Rectangle {
        visible: !root.compact
        Layout.preferredWidth: Style.space(185); Layout.fillHeight: true
        color: Util.alpha(Commons.Color.foreground, 0.02)
        Column {
          anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(12) }
          spacing: Style.space(5)
          Repeater {
            model: root.shortPages
            Ui.Button {
              required property int index
              required property string modelData
              objectName: "sidebarTab"
              width: parent.width
              tooltipText: root.pages[index]
              text: modelData; leftAlign: true; focusable: true
              selected: root.page === index
              fontSize: Style.font.body
              horizontalPadding: Style.space(12); verticalPadding: Style.space(12)
              Accessible.role: Accessible.PageTab; Accessible.name: root.pages[index]
              onClicked: root.page = index
            }
          }
        }
        Column {
          anchors { left: parent.left; right: parent.right; bottom: parent.bottom; margins: Style.space(20) }
          spacing: Style.space(8)
          Text { width: parent.width; text: strings.t("PRIVATE BY DEFAULT"); color: Commons.Color.muted; font { family: Style.font.family; pixelSize: Style.font.caption; letterSpacing: 0.6 } wrapMode: Text.WordWrap }
          Text { width: parent.width; text: strings.t("No PINs or passwords are collected in this window."); color: Commons.Color.muted; font { family: Style.font.family; pixelSize: Style.font.caption } wrapMode: Text.WordWrap; lineHeight: 1.3 }
          Ui.Button { text: strings.t("Help ↗"); focusable: true; fontSize: Style.font.caption; onClicked: root.guideRequested("control-center") }
        }
      }
      ColumnLayout {
        Layout.fillWidth: true; Layout.fillHeight: true; spacing: 0
        Flow {
          visible: root.compact
          Layout.fillWidth: true; Layout.margins: Style.space(8)
          spacing: Style.space(4)
          Repeater {
            model: root.shortPages
            Ui.Button { required property int index; required property string modelData; text: modelData; focusable: true; selected: root.page === index; fontSize: Style.font.caption; horizontalPadding: Style.space(7); onClicked: root.page = index }
          }
        }
        QQC.ScrollView {
          id: scroll
          objectName: "contentScroll"
          Layout.fillWidth: true; Layout.fillHeight: true
          contentWidth: availableWidth
          clip: true
          QQC.ScrollBar.horizontal.policy: QQC.ScrollBar.AlwaysOff
          ColumnLayout {
            width: scroll.availableWidth
            spacing: Style.space(14)
            Item { Layout.preferredHeight: Style.space(8) }
            ColumnLayout {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26)
              spacing: Style.space(7)
              Text { Layout.fillWidth: true; text: root.pages[root.page]; textFormat: Text.PlainText; color: Commons.Color.foreground; font { family: Style.font.family; pixelSize: Style.space(26); bold: true } wrapMode: Text.WordWrap }
              Text { Layout.fillWidth: true; text: root.subtitles[root.page]; textFormat: Text.PlainText; color: Commons.Color.muted; font { family: Style.font.family; pixelSize: Style.font.body } wrapMode: Text.WordWrap; lineHeight: 1.3 }
            }
            Rectangle {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26)
              visible: root.notice !== "" || !root.snapshot
              implicitHeight: noticeText.implicitHeight + Style.space(24)
              color: Util.alpha(root.failed ? Commons.Color.urgent : Commons.Color.accent, 0.09)
              radius: Style.cornerRadius
              Text {
                id: noticeText
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(12) }
                text: root.notice || strings.t("Checking your setup…")
                textFormat: Text.PlainText; wrapMode: Text.WordWrap
                color: root.failed ? Commons.Color.urgent : Commons.Color.foreground
                font { family: Style.font.family; pixelSize: Style.font.body }
                Accessible.role: Accessible.AlertMessage
              }
            }
            ColumnLayout {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26)
              visible: root.page === 0
              spacing: Style.space(14)
              FeatureCard {
                title: root.keyCount > 0 ? strings.t("%1 registered keys", [strings.number(root.keyCount)]) : strings.t("Start with your security key")
                badge: !root.snapshot ? strings.t("Checking…") : root.snapshot.connected === null ? strings.t("USB status unavailable") : strings.t("%1 connected", [strings.number(root.snapshot.connected)])
                ready: !!root.snapshot && root.snapshot.connected > 0
                description: root.keyCount > 0 ? strings.t("Registrations belong to your current Linux account. Keep a backup key in a separate place.") : strings.t("The guided installer offers sudo, desktop authentication and optional Keyring unlock. You review each change before it is applied.")
                ActionButton { text: strings.t("Guided setup"); primary: true; enabled: root.canAct; onClicked: root.ask("setup", text) }
                ActionButton { text: strings.t("Manage keys"); enabled: !!root.snapshot; onClicked: root.page = 1 }
              }
              FeatureCard {
                title: strings.t("Your session")
                description: strings.t("Status describes configuration. Test your key and password paths before relying on them.")
                Column {
                  width: parent.width
                  spacing: Style.space(12)
                  Repeater {
                    model: [ {label: strings.t("sudo authentication"), value: root.policy(root.snapshot ? root.snapshot.sudo : null)}, {label: strings.t("Desktop plugins"), value: root.desktopState()}, {label: strings.t("GNOME Keyring"), value: root.helperState()}, {label: strings.t("LUKS disk unlock"), value: strings.t("Separate enrollment")} ]
                    RowLayout {
                      required property var modelData
                      width: parent.width
                      Text { Layout.fillWidth: true; text: modelData.label; color: Commons.Color.foreground; font { family: Style.font.family; pixelSize: Style.font.body } wrapMode: Text.WordWrap }
                      Text { text: modelData.value; color: Commons.Color.accent; font { family: Style.font.family; pixelSize: Style.font.body } textFormat: Text.PlainText }
                    }
                  }
                }
              }
            }
            ColumnLayout {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26)
              visible: root.page === 1; spacing: Style.space(14)
              FeatureCard {
                title: strings.t("PAM security keys")
                badge: strings.t("%1 registered", [strings.number(root.keyCount)])
                ready: root.keyCount > 0
                description: strings.t("Add a PIN-protected backup key without changing shared authentication policy. Other accounts and existing keys are preserved.")
                ActionButton { text: strings.t("Add key / backup key"); primary: true; enabled: root.canAct && root.keyCount > 0; onClicked: root.ask("add-key", text) }
                ActionButton { text: strings.t("First-time setup"); enabled: root.canAct; onClicked: root.ask("setup", text) }
                ActionButton { text: strings.t("Remove a registration"); enabled: root.canAct && root.keyCount > 1; onClicked: root.ask("remove-key", text) }
              }
              FeatureCard {
                objectName: "openpgpCard"
                visible: root.openpgp.card
                title: strings.t("OpenPGP key on the card")
                badge: root.openpgpState()
                ready: root.openpgp.ready === true && !!root.openpgp.key && !root.openpgp.key.expired && !root.openpgp.key.revoked && !root.openpgp.key.disabled
                description: strings.t("Import the public key from the URL stored on the card or from the keyservers, so GnuPG signs and decrypts with the card. Removing it from the keyring leaves the key on the card.")
                details: Column {
                  objectName: "openpgpDetails"
                  width: parent.width
                  visible: root.openpgpRows.length > 0
                  spacing: Style.space(8)
                  Repeater {
                    model: root.openpgpRows
                    RowLayout {
                      required property var modelData
                      width: parent.width
                      spacing: Style.space(12)
                      Text { Layout.preferredWidth: Math.min(Style.space(130), parent.width * 0.35); text: modelData.label; color: Commons.Color.foreground; font { family: Style.font.family; pixelSize: Style.font.body } wrapMode: Text.WordWrap; textFormat: Text.PlainText }
                      TextEdit { Layout.fillWidth: true; Layout.minimumWidth: 0; text: modelData.value; readOnly: true; selectByMouse: true; wrapMode: TextEdit.WrapAnywhere; color: Commons.Color.accent; font { family: Style.font.family; pixelSize: Style.font.body } textFormat: TextEdit.PlainText }
                    }
                  }
                }
                // One button imports a missing key or removes an imported one; "Update
                // key" fetches an imported key again only when it needs attention.
                ActionButton { objectName: "openpgpUpdate"; text: strings.t("Update key"); primary: true; visible: root.openpgpNeedsUpdate(); enabled: root.canAct; onClicked: root.ask("openpgp-import", text) }
                ActionButton { objectName: "openpgpPrimary"; text: root.openpgp.imported ? strings.t("Remove from keyring") : strings.t("Import key"); primary: !root.openpgp.imported; enabled: root.canAct; onClicked: root.ask(root.openpgp.imported ? "openpgp-remove" : "openpgp-import", text) }
                ActionButton { text: strings.t("Trust as my key"); enabled: root.canAct && root.openpgp.imported && !root.openpgp.trusted; onClicked: root.ask("openpgp-trust", text) }
                ActionButton { objectName: "openpgpIdentityToggle"; text: root.showOpenpgpIdentity ? strings.t("Hide name and email") : strings.t("Show name and email"); visible: !!root.openpgp.key && !!root.openpgp.key.uid; onClicked: root.showOpenpgpIdentity = !root.showOpenpgpIdentity }
              }
              FeatureCard {
                objectName: "sshCard"
                title: strings.t("Resident SSH keys")
                badge: strings.t("%1 in ~/.ssh", [strings.number(root.sshCount)])
                ready: root.sshCount > 0
                description: strings.t("Create SSH keys on your security key, or copy the ones it stores into ~/.ssh, for example on a new computer. Existing files are never overwritten. Removing a copy leaves the key on the security key.")
                details: Column {
                  objectName: "sshKeys"
                  width: parent.width
                  visible: root.sshKeys.length > 0
                  spacing: Style.space(8)
                  Repeater {
                    model: root.sshKeys
                    RowLayout {
                      required property var modelData
                      required property int index
                      width: parent.width
                      spacing: Style.space(12)
                      Column {
                        Layout.fillWidth: true
                        Text { width: parent.width; text: modelData.application || strings.t("SSH key"); color: Commons.Color.foreground; font { family: Style.font.family; pixelSize: Style.font.body } textFormat: Text.PlainText; elide: Text.ElideRight }
                        Text { width: parent.width; text: root.sshKeyDetails(modelData); color: Util.alpha(Commons.Color.foreground, 0.73); font { family: Style.font.family; pixelSize: Style.font.caption } textFormat: Text.PlainText; wrapMode: Text.WrapAtWordBoundaryOrAnywhere }
                        TextEdit { width: parent.width; text: modelData.fingerprint; readOnly: true; selectByMouse: true; wrapMode: TextEdit.WrapAnywhere; color: Commons.Color.accent; font { family: Style.font.family; pixelSize: Style.font.caption } textFormat: TextEdit.PlainText }
                      }
                      ActionButton { objectName: "sshRemove" + index; text: strings.t("Remove"); enabled: root.canAct && !!modelData.id; onClicked: root.ask("ssh-remove", strings.t("Remove SSH key %1", [modelData.fingerprint.slice(0, 19)]), "", "", modelData.id) }
                    }
                  }
                }
                ActionButton { text: strings.t("Import SSH keys"); primary: root.sshCount === 0; enabled: root.canAct && root.snapshot.connected > 0; onClicked: root.ask("ssh-import", text) }
                ActionButton { objectName: "sshCreate"; text: strings.t("Create SSH key"); enabled: root.canAct && root.snapshot.connected > 0; onClicked: root.ask("ssh-create", text) }
              }
              FeatureCard {
                title: strings.t("A backup for every feature")
                description: strings.t("PAM, GNOME Keyring and LUKS keep separate enrollments. Add your backup key to each feature you use. Removing a PAM registration does not erase the physical key or revoke other enrollments.")
                ActionButton { text: strings.t("Keyring backup"); enabled: !!root.snapshot; onClicked: root.page = 3 }
                ActionButton { text: strings.t("Disk enrollment"); enabled: !!root.snapshot; onClicked: root.page = 4 }
                ActionButton { text: strings.t("Enrollment transfer guide ↗"); onClicked: root.guideRequested("enrollment-sync") }
              }
            }
            ColumnLayout {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26)
              visible: root.page === 2; spacing: Style.space(14)
              FeatureCard {
                title: strings.t("sudo authentication")
                badge: root.policy(root.snapshot ? root.snapshot.sudo : null)
                ready: !!root.snapshot && root.snapshot.sudo.state === "configured"
                description: strings.t("Use PIN + touch, with explicit password fallback by default. Setup preserves the original password stack and prints a rollback ID.")
                ActionButton { text: strings.t("Configure sudo"); primary: true; enabled: root.canAct; onClicked: root.ask("setup-sudo", text) }
                ActionButton { text: strings.t("Test sudo"); enabled: root.canAct; onClicked: root.ask("test-sudo", text) }
              }
              FeatureCard {
                title: strings.t("Lock screen & desktop approvals")
                badge: root.desktopState()
                ready: !!root.snapshot && root.snapshot.plugins.lock.enabled && root.snapshot.plugins.polkit.enabled
                description: strings.t("Set up the included lock and Polkit plugins together with their PAM services. Change authentication plugins only while the desktop is unlocked.")
                ActionButton { text: strings.t("Configure desktop"); primary: true; enabled: root.canAct; onClicked: root.ask("setup-desktop", text) }
                ActionButton { text: strings.t("Use standard plugins"); enabled: root.canAct && (root.snapshot.plugins.lock.enabled || root.snapshot.plugins.polkit.enabled); onClicked: root.ask("desktop-restore", text) }
              }
            }
            ColumnLayout {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26)
              visible: root.page === 3; spacing: Style.space(14)
              FeatureCard {
                title: strings.t("GNOME Keyring")
                badge: root.helperState(); ready: !!root.snapshot && root.snapshot.keyring.state === "enrolled"
                description: strings.t("Encrypts your existing keyring password using your key. The helper uses touch only, independently of PAM PIN settings. A FIDO2 key with hmac-secret is required.")
                ActionButton { text: strings.t("Set up Keyring"); primary: true; enabled: root.canAct; onClicked: root.ask("setup-keyring", text) }
                ActionButton { text: strings.t("Add backup key"); enabled: root.canAct && root.snapshot.keyring.installed && root.snapshot.keyring.count > 0; onClicked: root.ask("keyring-add", text) }
                ActionButton { text: strings.t("Test decryption"); enabled: root.canAct && root.snapshot.keyring.count > 0; onClicked: root.ask("keyring-check", text) }
                ActionButton { text: strings.t("Unlock now"); enabled: root.canAct && root.snapshot.keyring.count > 0; onClicked: root.ask("keyring-unlock", text) }
              }
              FeatureCard {
                title: strings.t("At graphical login")
                badge: root.snapshot && root.snapshot.keyring.autostart === "enabled" ? strings.t("Enabled") : strings.t("Not enabled")
                ready: !!root.snapshot && root.snapshot.keyring.autostart === "enabled"
                description: strings.t("Optionally ask for a key touch at login. Install the login service during Keyring setup before enabling it here.")
                ActionButton { text: strings.t("Enable at login"); enabled: root.canAct && root.snapshot.keyring.unit && root.snapshot.keyring.autostart !== "enabled"; onClicked: root.ask("keyring-enable", text) }
                ActionButton { text: strings.t("Disable at login"); enabled: root.canAct && root.snapshot.keyring.unit && root.snapshot.keyring.autostart === "enabled"; onClicked: root.ask("keyring-disable", text) }
              }
            }
            ColumnLayout {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26)
              visible: root.page === 4; spacing: Style.space(14)
              FeatureCard {
                title: strings.t("LUKS2 disk enrollment")
                badge: root.snapshot && root.snapshot.diskReady ? strings.t("Tools available") : strings.t("Check prerequisites")
                ready: !!root.snapshot && root.snapshot.diskReady
                description: strings.t("Choose your existing LUKS2 partition explicitly. Enrollment preserves passphrase slots and makes private header backups. Boot integration is a separate manual step.")
                Column {
                  width: parent.width; spacing: Style.space(10)
                  Ui.TextField { id: deviceField; objectName: "deviceField"; width: parent.width; placeholderText: "/dev/your-luks-partition"; Accessible.name: strings.t("LUKS2 device"); selectByMouse: true }
                  Flow {
                    width: parent.width; spacing: Style.space(8)
                    ActionButton { text: strings.t("Check device"); enabled: root.canAct && root.snapshot.diskReady && Model.parameters("luks-check", deviceField.text, "") !== null; onClicked: root.ask("luks-check", text, deviceField.text) }
                    ActionButton { text: strings.t("Enroll disk key"); enabled: root.canAct && root.snapshot.diskReady && Model.parameters("luks-enroll", deviceField.text, "") !== null; onClicked: root.ask("luks-enroll", text, deviceField.text) }
                    ActionButton { text: strings.t("Boot integration guide ↗"); onClicked: root.guideRequested("luks") }
                  }
                }
              }
              FeatureCard {
                title: strings.t("Restore a PAM backup")
                description: strings.t("Use the backup ID printed during setup. Restoration stops if files changed after that transaction. This does not undo Keyring, LUKS or plugin selection.")
                Column {
                  width: parent.width; spacing: Style.space(10)
                  Ui.TextField { id: backupField; objectName: "backupField"; width: parent.width; placeholderText: "YYYYMMDD-HHMMSS-xxxxxxxx"; Accessible.name: strings.t("PAM backup ID"); selectByMouse: true }
                  Flow {
                    width: parent.width; spacing: Style.space(8)
                    ActionButton { text: strings.t("Show backups"); enabled: root.canAct; onClicked: root.ask("backups", text) }
                    ActionButton { text: strings.t("Restore backup"); enabled: root.canAct && Model.parameters("rollback", "", backupField.text) !== null; onClicked: root.ask("rollback", text, "", backupField.text) }
                    ActionButton { text: strings.t("Recovery guide ↗"); onClicked: root.guideRequested("install") }
                  }
                }
              }
            }
            Text {
              Layout.fillWidth: true; Layout.leftMargin: Style.space(26); Layout.rightMargin: Style.space(26); Layout.bottomMargin: Style.space(22)
              text: root.busy ? strings.t("An operation is open in your terminal. Finish it there; status refreshes automatically.") : strings.t("Actions open a terminal for review and authentication. Keep a recovery root shell open while changing PAM.")
              color: Commons.Color.muted; font { family: Style.font.family; pixelSize: Style.font.caption }
              textFormat: Text.PlainText; wrapMode: Text.WordWrap; lineHeight: 1.3
            }
          }
        }
      }
    }
    Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: Util.alpha(Commons.Color.foreground, 0.13) }
    RowLayout {
      Layout.fillWidth: true; Layout.margins: Style.space(12)
      Text {
        Layout.fillWidth: true
        text: root.snapshot && !root.snapshot.supported ? strings.t("A compatible Omarchy desktop is required.") : strings.t("Local status · no credential values displayed")
        color: Commons.Color.muted; font { family: Style.font.family; pixelSize: Style.font.caption } wrapMode: Text.WordWrap
      }
      Text { text: "0.5.2"; color: Commons.Color.muted; font { family: Style.font.family; pixelSize: Style.font.caption } }
    }
  }
  Item {
    id: keyCatcher
    focus: true

  }
  Ui.ConfirmDialog {
    id: confirmation
    objectName: "actionConfirmation"
    anchors.fill: parent
    message: root.pendingTitle + "\n\n" + strings.t("Open an interactive terminal? Review the operation there before anything changes. PINs and passwords stay in that terminal.")
    cancelText: strings.t("Cancel")
    confirmText: strings.t("Open terminal")
    onCanceled: { opened = false; root.focusFirst() }
    onConfirmed: { opened = false; root.operationRequested(root.pendingAction, root.pendingParameters); root.focusFirst() }
  }
}
