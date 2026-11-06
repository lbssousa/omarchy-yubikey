// The GUI accepts metadata only. Secrets and command output never enter this model.
var actions = ["setup", "setup-sudo", "setup-desktop", "setup-keyring", "add-key", "remove-key", "test-sudo", "desktop-restore", "keyring-add", "keyring-check", "keyring-unlock", "keyring-enable", "keyring-disable", "luks-check", "luks-enroll", "openpgp-import", "openpgp-trust", "openpgp-remove", "ssh-create", "ssh-import", "ssh-remove", "backups", "rollback"]
function count(value) { return typeof value === "number" && isFinite(value) && value >= 0 && value <= 1000 ? Math.floor(value) : 0 }
function state(value) { return ["configured", "external", "unreadable", "not-configured"].indexOf(value) >= 0 ? value : "not-configured" }
function publicText(value) { return typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, "").slice(0, 256) : "" }
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
  out.openpgp = {card: openpgp.card === true, imported: openpgp.imported === true, linked: openpgp.linked === true, trusted: openpgp.trusted === true, ready: openpgp.ready === true, local: openpgp.local === true, key: null, slots: {}}
  var roles = ["sign", "encrypt", "authenticate"]
  roles.forEach(function(role) {
    var slot = (openpgp.slots || {})[role]
    if (slot && typeof slot === "object") out.openpgp.slots[role] = {present: slot.present === true, linked: slot.linked === true, ready: slot.ready === true, location: ["card", "other-card", "disk", "missing"].indexOf(slot.location) >= 0 ? slot.location : "missing"}
  })
  var key = openpgp.key
  if (out.openpgp.imported && key && typeof key === "object") {
    out.openpgp.key = {
      algorithm: typeof key.algorithm === "string" && /^(rsa[0-9]{4,5}|ed25519|ed448|cv25519|cv448|nistp(256|384|521)|brainpoolP(256|384|512)r1|secp256k1)$/.test(key.algorithm) ? key.algorithm : "other",
      expires: typeof key.expires === "string" && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(key.expires) ? key.expires : "",
      expired: key.expired === true, revoked: key.revoked === true, disabled: key.disabled === true, uids: count(key.uids),
      fingerprint: typeof key.fingerprint === "string" && /^(?:[A-F0-9]{40}|[A-F0-9]{64})$/.test(key.fingerprint) ? key.fingerprint : "",
      uid: publicText(key.uid),
      sign: key.sign === true, encrypt: key.encrypt === true, authenticate: key.authenticate === true}
  }
  var ssh = value.ssh || {}
  out.ssh = {count: count(ssh.count), modified: ssh.modified === true, keys: (Array.isArray(ssh.keys) ? ssh.keys : []).slice(0, 50).filter(function(key) {
    return key && typeof key.id === "string" && /^[0-9a-f]{64}$/.test(key.id)
  }).map(function(key) {
    return {id: key.id, type: ["ed25519-sk", "ecdsa-sk"].indexOf(key.type) >= 0 ? key.type : "other", passphrase: key.passphrase === true, host: key.host === true,
      application: typeof key.application === "string" && /^ssh:[\x21-\x7e]{0,252}$/.test(key.application) ? key.application : "",
      fingerprint: typeof key.fingerprint === "string" && /^SHA256:[A-Za-z0-9+/]{43}$/.test(key.fingerprint) ? key.fingerprint : ""}
  })}
  var tools = value.tools || {}
  out.diskReady = tools.cryptsetup === true && tools["systemd-cryptenroll"] === true && tools["fido2-token"] === true
  var operation = value.operation || {}
  out.operation = {action: actions.indexOf(operation.action) >= 0 ? operation.action : "", phase: ["starting", "running", "succeeded", "failed", "cancelled", "interrupted"].indexOf(operation.phase) >= 0 ? operation.phase : ""}
  return out
}
function parameters(action, device, backup, keyId) {
  if (actions.indexOf(action) < 0) return null
  var result = []
  if (action === "luks-check" || action === "luks-enroll") {
    if (!/^\/dev\/[A-Za-z0-9_./:-]+$/.test(device || "") || String(device).split("/").indexOf("..") >= 0) return null
    result = ["--device", device]
  } else if (action === "rollback") {
    if (!/^[0-9]{8}-[0-9]{6}-[a-f0-9]{8}$/.test(backup || "")) return null
    result = ["--backup", backup]
  } else if (action === "ssh-remove") {
    if (typeof keyId !== "string" || !/^[0-9a-f]{64}$/.test(keyId)) return null
    result = ["--key-id", keyId]
  }
  return result
}
if (typeof module !== "undefined") module.exports = {actions: actions, count: count, cleanSnapshot: cleanSnapshot, parameters: parameters}
