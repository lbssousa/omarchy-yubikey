import QtQuick
import Quickshell
import Quickshell.Io
import "Locale.js" as Locale

// Omarchy 4.5 supplies Commons.Translations. The local loader keeps the same
// catalogs usable on older supported shells, without changing the host config.
QtObject {
  id: root
  property var nativeTranslations: null
  readonly property string configHome: Quickshell.env("XDG_CONFIG_HOME") || Quickshell.env("HOME") + "/.config"
  readonly property var registry: Locale.parse(registryFile.text())
  readonly property string language: Locale.normalize(Quickshell.env("OMARCHY_YUBIKEY_LANGUAGE") || languageFile.text() ||
    Quickshell.env("LC_ALL") || Quickshell.env("LC_MESSAGES") || Quickshell.env("LANGUAGE") || Quickshell.env("LANG"), registry)
  readonly property string baseLanguage: language.split("-")[0]
  readonly property bool rightToLeft: (registry[language] || {}).direction === "rtl"
  readonly property var english: Locale.parse(englishFile.text())
  readonly property var baseStrings: Locale.parse(baseFile.text())
  readonly property var translated: Locale.parse(translatedFile.text())
  readonly property var fallbackPrompts: {
    try { return JSON.parse(fallbackFile.text() || "[]") } catch (error) { return [] }
  }

  function t(source, values) {
    var template = translated[source] || baseStrings[source] || english[source] || source
    if (nativeTranslations) template = nativeTranslations.t(source, template)
    return Locale.render(template, values)
  }

  function number(value) {
    var zero = (registry[language] || {}).zeroDigit || "0"
    return String(value).replace(/[0-9]/g, function(digit) { return String.fromCharCode(zero.charCodeAt(0) + Number(digit)) })
  }

  Component.onCompleted: {
    if (Quickshell.env("OMARCHY_YUBIKEY_LANGUAGE")) return
    try {
      nativeTranslations = Qt.createQmlObject('import QtQuick; import qs.Commons as Commons; Commons.Translations {}', root, "yubikey-native-translations")
      nativeTranslations.directory = Qt.resolvedUrl("i18n")
    } catch (error) {
      // Older hosts do not export Commons.Translations; use the local loader.
    }
  }

  property FileView languageFile: FileView {
    path: Quickshell.env("OMARCHY_LANGUAGE_FILE") || root.configHome + "/omarchy/language"
    watchChanges: true; blockLoading: true; printErrors: false
    onFileChanged: reload()
  }
  property FileView registryFile: FileView {
    path: Qt.resolvedUrl("i18n/locales.json"); blockLoading: true; printErrors: false
  }
  property FileView englishFile: FileView {
    path: Qt.resolvedUrl("i18n/en.json"); blockLoading: true; printErrors: false
  }
  property FileView baseFile: FileView {
    path: root.baseLanguage !== root.language ? Qt.resolvedUrl("i18n/" + root.baseLanguage + ".json") : ""
    blockLoading: true; printErrors: false
  }
  property FileView translatedFile: FileView {
    path: root.language !== "en" ? Qt.resolvedUrl("i18n/" + root.language + ".json") : ""
    blockLoading: true; printErrors: false
  }
  property FileView fallbackFile: FileView {
    path: Qt.resolvedUrl("i18n/fallback-prompts.json"); blockLoading: true; printErrors: false
  }
}
