// Locale normalization and substitution are shared by the compatibility loader
// and its Node tests. Values are inserted once and are never interpreted.
function normalize(value, registry) {
  var code = String(value || "").trim().split(":")[0].split(".")[0].split("@")[0].replace(/_/g, "-")
  var names = Object.keys(registry)
  for (var i = 0; i < names.length; i++)
    if (names[i].toLowerCase() === code.toLowerCase()) return names[i]
  var lower = code.toLowerCase()
  var base = lower.split("-")[0]
  var aliases = {es: "es-MX", nb: "no", nn: "no", tl: "fil", zh: "zh-CN"}
  if (lower === "zh-hk" || lower === "zh-hant") return "zh-TW"
  return aliases[base] || (registry[base] ? base : "en")
}

function render(source, values) {
  return String(source).replace(/%([1-9][0-9]*)/g, function(token, number) {
    return values && Number(number) <= values.length ? String(values[Number(number) - 1]) : token
  })
}

function parse(raw) {
  try {
    var value = JSON.parse(raw || "{}")
    return value && typeof value === "object" && !Array.isArray(value) ? value : ({})
  } catch (error) { return ({}) }
}

if (typeof module !== "undefined") module.exports = {normalize: normalize, render: render, parse: parse}
