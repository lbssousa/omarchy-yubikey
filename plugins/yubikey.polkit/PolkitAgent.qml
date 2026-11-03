import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Services.Polkit
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "PolkitModel.js" as PolkitModel

Item {
  id: root

  property string fontFamily: Style.font.menuFamily
  // Bound to the central [polkit] section in shell.toml via Color.qml.
  property color accent: Color.polkit.accent
  property color background: Color.polkit.background
  property color foreground: Color.polkit.text
  property color border: Color.polkit.border
  property color borderError: Color.polkit.borderError
  property var borderSpec: Border.surfaceSpec("polkit", errorFlash ? "border-error" : "border", errorFlash ? borderError : border, Math.max(1, Style.space(2)), "border-alpha")
  property color scrim: Color.polkit.scrim
  readonly property int cornerRadius: Style.cornerRadius
  property int contentMargin: Style.spacing.panelPadding
  property int fieldHeight: Math.max(Style.space(42), Style.spacing.controlHeight)

  property bool closing: false
  property bool submitted: false
  property string currentMessage: ""
  property string currentPrompt: ""
  property string currentSupplementary: ""
  property bool responseRequired: false
  property bool responseVisible: false
  property bool failed: false
  property bool errorFlash: false
  // pam_fprintd appears in the polkit PAM stack (a sensor is enrolled).
  property bool fingerprintConfigured: false
  // pam_u2f appears in the polkit PAM stack (a FIDO2 key is registered).
  property bool fido2Configured: false
  // Lid shut right now — the reader is physically unreachable, so we fall back
  // to the password even when a sensor is enrolled. Refreshed per request.
  property bool laptopClosed: false
  property int shakeOffset: 0

  readonly property bool dialogVisible: polkitAgent.isActive || closing
  // We show one method at a time. Fingerprint owns the dialog while PAM is
  // waiting on the reader (lid open, sensor enrolled); the moment PAM asks for
  // a password — including immediately when the lid is shut and the clamshell
  // gate skips pam_fprintd — we switch to the password field instead.
  readonly property bool fingerprintMode: fingerprintConfigured && !laptopClosed && dialogVisible && !responseRequired && !submitted && !errorFlash
  // Key mode: PAM is waiting on the FIDO2 key. The field stays usable so a
  // password typed meanwhile is ready the moment PAM falls back to asking.
  // Typed ahead while the key was still being waited for: show the field.
  property bool typingAhead: false
  readonly property bool keyWaiting: fido2Configured && !fingerprintMode && dialogVisible && !responseRequired && !submitted && !errorFlash
  // Wide card with key glyph + field (typing ahead), or the square key pane.
  readonly property bool fido2Mode: keyWaiting && typingAhead
  readonly property bool fido2Square: keyWaiting && !typingAhead
  readonly property int squareSize: Style.space(168)
  readonly property int baseCardHeight: panel.height > 0 ? Math.min(fieldHeight + contentMargin * 2, panel.height - Style.gapsOut * 2) : fieldHeight + contentMargin * 2
  readonly property int cardHeight: fido2Square ? squareSize : baseCardHeight
  // Password mode is a wide field; fingerprint mode collapses to a square that
  // just frames the centered sensor icon.
  readonly property int cardWidth: (fingerprintMode || fido2Square) ? cardHeight : Math.min(Style.space(312), Math.max(Style.space(260), panel.width - Style.gapsOut * 2))

  function authorizationLabel(message) {
    return PolkitModel.authorizationLabel(message)
  }

  function loadPamConfig(raw) {
    fingerprintConfigured = PolkitModel.fingerprintConfiguredFromPamConfig(raw)
    fido2Configured = PolkitModel.fido2ConfiguredFromPamConfig(raw)
  }

  function refreshLidState() {
    if (!laptopClosedProc.running) laptopClosedProc.running = true
  }

  function resetSnapshot() {
    currentMessage = ""
    currentPrompt = ""
    currentSupplementary = ""
    responseRequired = false
    responseVisible = false
    failed = false
    errorFlash = false
    submitted = false
    typingAhead = false
    passwordInput.text = ""
  }

  function syncFromFlow() {
    var flow = polkitAgent.flow
    if (!flow) return

    currentMessage = String(flow.message || "Authentication is needed...")
    currentPrompt = String(flow.inputPrompt || "")
    currentSupplementary = String(flow.supplementaryMessage || "")
    responseRequired = !!flow.isResponseRequired
    responseVisible = !!flow.responseVisible
    failed = !!flow.failed

    if (responseRequired) submitted = false
  }

  function beginFlow() {
    closeTimer.stop()
    closing = false
    submitted = false
    typingAhead = false
    passwordInput.text = ""
    refreshLidState()
    syncFromFlow()
    Qt.callLater(refocus)
  }

  function refocus() {
    if (!dialogVisible) return
    // In fingerprint mode there is no field to type into — park focus on the
    // key catcher so Escape still cancels; otherwise focus the password field.
    if (fingerprintMode || fido2Square) keyCatcher.forceActiveFocus()
    else passwordInput.forceActiveFocus()
  }

  function submitResponse() {
    var flow = polkitAgent.flow
    if (!flow || !flow.isResponseRequired) return
    submitted = true
    errorFlash = false
    flow.submit(passwordInput.text)
    passwordInput.text = ""
    keyCatcher.forceActiveFocus()
  }

  function cancelRequest() {
    var flow = polkitAgent.flow
    passwordInput.text = ""
    submitted = false
    closing = true
    closeTimer.restart()
    if (flow) flow.cancelAuthenticationRequest()
  }

  function triggerFailureFeedback() {
    submitted = false
    errorFlash = true
    passwordInput.text = ""
    errorTimer.restart()
    shakeAnimation.restart()
    Qt.callLater(refocus)
  }

  Timer {
    id: closeTimer
    interval: 300
    repeat: false
    onTriggered: {
      closing = false
      resetSnapshot()
    }
  }

  Timer {
    id: errorTimer
    interval: 1200
    repeat: false
    onTriggered: root.errorFlash = false
  }

  SequentialAnimation {
    id: shakeAnimation
    NumberAnimation { target: root; property: "shakeOffset"; to: -8; duration: 35; easing.type: Easing.OutQuad }
    NumberAnimation { target: root; property: "shakeOffset"; to: 8; duration: 50; easing.type: Easing.InOutQuad }
    NumberAnimation { target: root; property: "shakeOffset"; to: 0; duration: 55; easing.type: Easing.OutQuad }
  }
  FileView {
    path: "/etc/pam.d/polkit-1"
    watchChanges: true
    printErrors: false
    onLoaded: root.loadPamConfig(text())
    onLoadFailed: { root.fingerprintConfigured = false; root.fido2Configured = false }
    onFileChanged: reload()
  }

  Process {
    id: laptopClosedProc
    command: ["bash", "-c", "omarchy-hw-laptop-closed && echo closed || echo open"]
    stdout: StdioCollector { id: laptopClosedOut; waitForEnd: true }
    onExited: root.laptopClosed = String(laptopClosedOut.text || "").trim() === "closed"
  }

  PolkitAgent {
    id: polkitAgent
    path: "/org/omarchy/PolkitAgent"

    onAuthenticationRequestStarted: root.beginFlow()
    onIsActiveChanged: {
      if (isActive) root.syncFromFlow()
      else if (!root.closing) root.resetSnapshot()
    }
    onIsRegisteredChanged: {
      if (isRegistered) console.log("omarchy polkit agent registered")
      else console.warn("omarchy polkit agent is not registered; another agent may be running")
    }
  }

  Connections {
    target: polkitAgent.flow

    function onIsResponseRequiredChanged() {
      root.syncFromFlow()
      if (!polkitAgent.flow || !polkitAgent.flow.isResponseRequired) passwordInput.text = ""
      Qt.callLater(root.refocus)
    }

    function onInputPromptChanged() { root.syncFromFlow() }
    function onResponseVisibleChanged() { root.syncFromFlow() }
    function onSupplementaryMessageChanged() { root.syncFromFlow() }
    function onFailedChanged() { root.syncFromFlow() }

    function onAuthenticationFailed() {
      root.syncFromFlow()
      root.triggerFailureFeedback()
    }

    function onAuthenticationSucceeded() {
      root.closing = true
      closeTimer.restart()
    }

    function onAuthenticationRequestCancelled() {
      root.closing = true
      closeTimer.restart()
    }
  }

  PanelWindow {
    id: panel
    visible: root.dialogVisible
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "omarchy-polkit"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    Rectangle {
      anchors.fill: parent
      color: root.scrim
    }

    MouseArea {
      anchors.fill: parent
      onClicked: root.refocus()
    }

    // Key mode: a soft accent frame breathing around the card signals "waiting
    // for a touch" before any text is read.
    Rectangle {
      id: keyGlow
      visible: root.keyWaiting
      anchors.centerIn: card
      anchors.horizontalCenterOffset: root.shakeOffset
      width: card.width + Style.space(12)
      height: card.height + Style.space(12)
      radius: root.cornerRadius + Style.space(6)
      color: "transparent"
      border.width: Math.max(1, Style.space(2))
      border.color: root.accent
      opacity: 0.18
    }

    BorderSurface {
      id: card
      width: root.cardWidth
      height: root.cardHeight
      radius: root.cornerRadius
      anchors.centerIn: parent
      anchors.horizontalCenterOffset: root.shakeOffset
      color: root.background
      borderSpec: root.borderSpec
      padding: root.contentMargin
      Behavior on width { NumberAnimation { duration: 220; easing.type: Easing.OutCubic } }
      Behavior on height { NumberAnimation { duration: 220; easing.type: Easing.OutCubic } }

      MouseArea { anchors.fill: parent; onClicked: root.refocus() }

      Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true

        Keys.priority: Keys.BeforeItem
        Keys.onPressed: function(event) {
          if (event.key === Qt.Key_Escape) {
            root.cancelRequest()
            event.accepted = true
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            if (root.responseRequired) root.submitResponse()
            event.accepted = true
          } else if (root.fido2Square && event.text.length > 0 && !(event.modifiers & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier))) {
            root.typingAhead = true
            passwordInput.text = event.text
            Qt.callLater(function() { passwordInput.forceActiveFocus(); passwordInput.cursorPosition = passwordInput.text.length })
            event.accepted = true
          }
        }
      }

      // Square key pane: glyph in the middle, rotating accent arc and a pulse
      // ring around it, the two-line hint underneath.
      Item {
        id: keyPane
        anchors.fill: parent
        visible: root.fido2Square
        readonly property int glyphBox: Math.round(root.squareSize * 0.42)

        Column {
          anchors.centerIn: parent
          spacing: Style.space(10)

          Item {
            id: keyStage
            width: keyPane.glyphBox
            height: keyPane.glyphBox
            anchors.horizontalCenter: parent.horizontalCenter

            // Soft disc behind the glyph with a slow, barely-there pulse.
            Rectangle {
              id: squareHalo
              anchors.centerIn: parent
              width: parent.width * 0.74
              height: width
              radius: width / 2
              color: root.accent
              opacity: 0.10
              SequentialAnimation on opacity {
                running: root.fido2Square
                loops: Animation.Infinite
                NumberAnimation { to: 0.16; duration: 1600; easing.type: Easing.InOutSine }
                NumberAnimation { to: 0.08; duration: 1600; easing.type: Easing.InOutSine }
              }
            }

            // Thin static ring framing the disc.
            Rectangle {
              anchors.centerIn: parent
              width: parent.width * 0.92
              height: width
              radius: width / 2
              color: "transparent"
              border.width: Math.max(1, Style.space(1))
              border.color: root.accent
              opacity: 0.35
            }



            OpticalGlyph {
              id: squareGlyph
              anchors.centerIn: parent
              width: Math.round(keyPane.glyphBox * 0.5)
              height: width
              text: "\udb80\udf06"
              color: root.accent
              fontFamily: root.fontFamily
              fontSize: Math.round(keyPane.glyphBox * 0.42)
            }
          }

          Text {
            textFormat: Text.PlainText
            anchors.horizontalCenter: parent.horizontalCenter
            text: "Touch your key"
            color: root.foreground
            opacity: 0.92
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading
            font.weight: Font.DemiBold
          }

          Text {
            textFormat: Text.PlainText
            anchors.horizontalCenter: parent.horizontalCenter
            text: "or just start typing"
            color: root.foreground
            opacity: 0.42
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
        }
      }

      // Fingerprint mode shows just the sensor icon, centered and alone \u2014 no
      // padlock, no field, no prompt text.
      OpticalGlyph {
        anchors.centerIn: parent
        width: Math.round(root.fieldHeight * 0.7)
        height: width
        visible: root.fingerprintMode
        text: "\udb80\ude37"
        fontFamily: root.fontFamily
        fontSize: Math.round(root.fieldHeight * 0.7)
        color: root.errorFlash ? Color.polkit.textError : root.accent
      }

      Row {
        id: cardRow
        visible: !root.fingerprintMode && !root.fido2Square
        anchors.fill: parent
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.bottomMargin: card.contentBottomInset
        anchors.leftMargin: card.contentLeftInset
        spacing: Style.space(14)

        Item {
          id: glyphSlot
          width: root.fido2Mode ? Style.space(36) : Style.space(26)
          height: root.fieldHeight
          Behavior on width { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }


          // Filled pulse behind the glyph, so the key reads as "live".
          Rectangle {
            id: keyHalo
            anchors.centerIn: parent
            width: Style.space(28)
            height: width
            radius: width / 2
            color: root.accent
            visible: root.fido2Mode
            opacity: 0.12

            SequentialAnimation on opacity {
              running: root.fido2Mode
              loops: Animation.Infinite
              NumberAnimation { to: 0.18; duration: 1600; easing.type: Easing.InOutSine }
              NumberAnimation { to: 0.09; duration: 1600; easing.type: Easing.InOutSine }
            }
          }

          OpticalGlyph {
            id: modeGlyph
            anchors.centerIn: parent
            width: Style.space(24)
            height: width
            text: root.fido2Mode ? "\udb80\udf06" : "\uf023"
            color: root.errorFlash ? Color.polkit.textError : root.accent
            fontFamily: root.fontFamily
            fontSize: root.fido2Mode ? Math.round(Style.font.iconLarge * 1.1) : Style.font.iconLarge
          }
        }

        Item {
          width: parent.width - Style.space(40)
          height: root.fieldHeight

          TextInput {
            id: passwordInput
            anchors.fill: parent
            verticalAlignment: TextInput.AlignVCenter
            activeFocusOnPress: true
            clip: true
            selectionColor: Util.alpha(root.accent, 0.45)
            selectedTextColor: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.iconLarge
            echoMode: root.responseVisible ? TextInput.Normal : TextInput.Password
            passwordCharacter: "\u2022"
            color: root.errorFlash ? Color.polkit.textError : root.foreground
            cursorVisible: activeFocus && !root.submitted && !root.errorFlash
            readOnly: root.submitted || root.errorFlash
            enabled: root.dialogVisible
            onAccepted: root.submitResponse()
            Keys.onPressed: function(event) {
              if (event.key === Qt.Key_Escape) {
                root.cancelRequest()
                event.accepted = true
              }
            }
          }

          Column {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Math.max(1, Style.space(1))
            visible: passwordInput.text.length === 0

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.errorFlash ? "Wrong" : (root.submitted ? "Checking..." : (root.fido2Mode ? "Touch your key" : "Enter password"))
              color: root.errorFlash ? Color.polkit.textError : root.foreground
              opacity: root.errorFlash ? 1 : (root.fido2Mode && !root.submitted ? 0.92 : 0.36)
              font.family: root.fontFamily
              font.pixelSize: root.fido2Mode && !root.errorFlash && !root.submitted ? Style.font.heading : Style.font.iconLarge
              font.weight: root.fido2Mode && !root.errorFlash && !root.submitted ? Font.DemiBold : Font.Normal
              elide: Text.ElideRight
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              visible: root.fido2Mode && !root.errorFlash && !root.submitted
              text: "or type your password"
              color: root.foreground
              opacity: 0.42
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideRight
            }
          }

          Rectangle {
            width: Math.max(1, Style.space(2))
            height: Style.space(24)
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            color: root.errorFlash ? Color.polkit.textError : root.foreground
            visible: passwordInput.visible && passwordInput.activeFocus && passwordInput.text.length === 0 && !root.submitted && !root.errorFlash && !root.fido2Mode
          }

          MouseArea {
            anchors.fill: parent
            acceptedButtons: Qt.LeftButton
            enabled: passwordInput.visible
            onClicked: passwordInput.forceActiveFocus()
          }
        }
      }
    }

    Rectangle {
      width: Math.min(justificationText.implicitWidth + Style.space(24), panel.width - Style.gapsOut * 2)
      height: Style.space(28)
      anchors.horizontalCenter: card.horizontalCenter
      anchors.bottom: card.top
      anchors.bottomMargin: Style.space(10)
      radius: root.cornerRadius
      color: root.background

      Text {
        id: justificationText
        textFormat: Text.PlainText
        anchors.fill: parent
        anchors.leftMargin: Style.space(12)
        anchors.rightMargin: Style.space(12)
        text: root.authorizationLabel(root.currentMessage)
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideMiddle
      }
    }
  }
}
