// Power actions offered at the bottom of the lock screen, without unlocking.
// Loaded by LockView.qml and Service.qml and, in the tests, by node
// (module.exports at the bottom), so no QML here.
//
// `id` is the key in the capability probe's JSON and selects the systemctl
// verb. The F keys match the SDDM greeter's power keys, so a key does the same
// on both screens (F2 would be hibernate there). `confirm` marks the actions
// that end every open session: they ask first; suspend leaves sessions as
// they are.

var actions = [
  { id: "suspend", verb: "suspend", fkey: 1, icon: "󰒲", confirm: false },
  { id: "reboot", verb: "reboot", fkey: 3, icon: "󰜉", confirm: true },
  { id: "powerOff", verb: "poweroff", fkey: 4, icon: "󰐥", confirm: true }
]

// Seconds a question waits for Enter before it goes away by itself.
var CONFIRM_TIMEOUT_MS = 10000

// Unreadable capabilities offer nothing, rather than actions that would fail.
function parseCapabilities(text) {
  try {
    var caps = JSON.parse(String(text || ""))
    return caps && typeof caps === "object" && !Array.isArray(caps) ? caps : {}
  } catch (e) {
    return {}
  }
}

function available(caps) {
  return actions.filter(function (action) {
    return !!caps && caps[action.id] === true
  })
}

// The action F<n> runs among those offered, or null.
function forFKey(offered, n) {
  var list = offered || []
  for (var i = 0; i < list.length; i++) {
    if (list[i].fkey === n) return list[i]
  }
  return null
}

// The fixed command for an offered action; null for anything else.
function command(action) {
  for (var i = 0; i < actions.length; i++) {
    if (action && actions[i].id === action.id) return ["systemctl", actions[i].verb]
  }
  return null
}

if (typeof module !== "undefined") {
  module.exports = {
    actions: actions,
    CONFIRM_TIMEOUT_MS: CONFIRM_TIMEOUT_MS,
    parseCapabilities: parseCapabilities,
    available: available,
    forFKey: forFKey,
    command: command
  }
}
