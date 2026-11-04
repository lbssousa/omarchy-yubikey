import QtQuick
import Quickshell
import Quickshell.Io
import "../i18n/runtime/Locale.js" as Locale

QtObject {
  id: root
  readonly property string configHome: Quickshell.env("XDG_CONFIG_HOME") || Quickshell.env("HOME") + "/.config"
  readonly property var registry: Locale.parse(registryFile.text())
  readonly property string language: Locale.normalize(Quickshell.env("OMARCHY_YUBIKEY_LANGUAGE") || languageFile.text() || Quickshell.env("LC_ALL") || Quickshell.env("LC_MESSAGES") || Quickshell.env("LANGUAGE") || Quickshell.env("LANG"), registry)
  readonly property bool rightToLeft: (registry[language] || {}).direction === "rtl"
  readonly property var english: Locale.parse(englishFile.text())
  readonly property var translated: Locale.parse(translatedFile.text())
  function t(source, values) { return Locale.render(translated[source] || english[source] || source, values) }
  function number(value) {
    var zero = (registry[language] || {}).zeroDigit || "0"
    return String(value).replace(/[0-9]/g, function(digit) { return String.fromCharCode(zero.charCodeAt(0) + Number(digit)) })
  }
  property FileView languageFile: FileView {
    path: Quickshell.env("OMARCHY_LANGUAGE_FILE") || root.configHome + "/omarchy/language"
    watchChanges: true; blockLoading: true; printErrors: false
    onFileChanged: reload()
  }
  property FileView registryFile: FileView { path: Qt.resolvedUrl("../i18n/locales.json"); blockLoading: true; printErrors: false }
  property FileView englishFile: FileView { path: Qt.resolvedUrl("../i18n/control/en.json"); blockLoading: true; printErrors: false }
  property FileView translatedFile: FileView {
    path: root.language === "de" ? Qt.resolvedUrl("../i18n/control/de.json") : ""
    blockLoading: true; printErrors: false
  }
}
