// The GUI accepts metadata only. Secrets and command output never enter this model.
var actions = ["setup", "setup-sudo", "setup-desktop", "setup-keyring", "add-key", "remove-key", "test-sudo", "desktop-restore", "keyring-add", "keyring-check", "keyring-unlock", "keyring-enable", "keyring-disable", "luks-check", "luks-enroll", "openpgp-import", "openpgp-trust", "openpgp-remove", "backups", "rollback"]
function count(value) { return typeof value === "number" && isFinite(value) && value >= 0 && value <= 1000 ? Math.floor(value) : 0 }
function state(value) { return ["configured", "external", "unreadable", "not-configured"].indexOf(value) >= 0 ? value : "not-configured" }
function cleanSnapshot(value) {
  if (!value || value.schema !== 1 || value.ok !== true) return null
  var out = {supported: value.supported === true, connected: value.connected === null ? null : count(value.connected)}
  var enrollment = value.enrollment || {}
  out.enrollment = {count: count(enrollment.count), state: ["enrolled", "not-enrolled", "unreadable"].indexOf(enrollment.state) >= 0 ? enrollment.state : "unreadable"}
  for (var i = 0; i < 3; i++) {
    var role = ["sudo", "polkit", "lock"][i], source = value[role] || {}
    out[role] = {state: state(source.state), pin: source.pin === true, explicit: source.explicit === true}
  }
  out.plugins = {}
  for (var j = 0; j < 2; j++) {
    var name = ["lock", "polkit"][j], plugin = (value.plugins || {})[name] || {}
    out.plugins[name] = {installed: plugin.installed === true, enabled: plugin.enabled === true}
  }
  var keyring = value.keyring || {}
  out.keyring = {installed: keyring.installed === true, unit: keyring.unit === true, count: count(keyring.count), state: ["enrolled", "not-enrolled", "unreadable"].indexOf(keyring.state) >= 0 ? keyring.state : "unreadable", autostart: keyring.autostart === "enabled" ? "enabled" : "disabled"}
  var openpgp = value.openpgp || {}
  out.openpgp = {card: openpgp.card === true, imported: openpgp.imported === true, linked: openpgp.linked === true, trusted: openpgp.trusted === true}
  var tools = value.tools || {}
  out.diskReady = tools.cryptsetup === true && tools["systemd-cryptenroll"] === true && tools["fido2-token"] === true
  var operation = value.operation || {}
  out.operation = {action: actions.indexOf(operation.action) >= 0 ? operation.action : "", phase: ["starting", "running", "succeeded", "failed", "cancelled", "interrupted"].indexOf(operation.phase) >= 0 ? operation.phase : ""}
  return out
}
function parameters(action, device, backup) {
  if (actions.indexOf(action) < 0) return null
  var result = []
  if (action === "luks-check" || action === "luks-enroll") {
    if (!/^\/dev\/[A-Za-z0-9_./:-]+$/.test(device || "") || String(device).split("/").indexOf("..") >= 0) return null
    result = ["--device", device]
  } else if (action === "rollback") {
    if (!/^[0-9]{8}-[0-9]{6}-[a-f0-9]{8}$/.test(backup || "")) return null
    result = ["--backup", backup]
  }
  return result
}
if (typeof module !== "undefined") module.exports = {actions: actions, count: count, cleanSnapshot: cleanSnapshot, parameters: parameters}
