//! Embedded display catalogs. Language selection never changes credential data.
use serde_json::Value;
use std::{env, fs, path::PathBuf, sync::LazyLock};

include!(concat!(env!("OUT_DIR"), "/catalogs.rs"));

macro_rules! tr {
    ($source:literal $(, $value:expr)* $(,)?) => {
        $crate::i18n::text($source, &[$($value.to_string()),*])
    };
}

static REGISTRY: LazyLock<Value> =
    LazyLock::new(|| serde_json::from_str(CATALOGS.iter().find(|(code, _)| *code == "locales").unwrap().1).unwrap());
static LANGUAGE: LazyLock<String> = LazyLock::new(current_language);
static STRINGS: LazyLock<Value> = LazyLock::new(|| {
    let mut merged = serde_json::Map::new();
    for wanted in ["en", LANGUAGE.split('-').next().unwrap_or("en"), LANGUAGE.as_str()] {
        if let Some((_, raw)) = CATALOGS.iter().find(|(code, _)| *code == wanted) {
            if let Ok(Value::Object(catalog)) = serde_json::from_str(raw) {
                merged.extend(catalog);
            }
        }
    }
    Value::Object(merged)
});

pub fn normalize(value: &str) -> String {
    let code = value.trim().split([':', '.', '@']).next().unwrap_or("").replace('_', "-");
    if let Some(known) = REGISTRY.as_object().unwrap().keys().find(|known| known.eq_ignore_ascii_case(&code)) {
        return known.clone();
    }
    let lower = code.to_lowercase();
    let mapped = match lower.as_str() {
        "es" => "es-MX",
        "nb" | "nn" => "no",
        "tl" => "fil",
        "zh" | "zh-hans" => "zh-CN",
        "zh-hk" | "zh-hant" => "zh-TW",
        _ => match lower.split('-').next().unwrap_or("en") {
            "es" => "es-MX",
            "nb" | "nn" => "no",
            "tl" => "fil",
            "zh" => "zh-CN",
            base => base,
        },
    };
    if REGISTRY.get(mapped).is_some() {
        mapped.into()
    } else {
        "en".into()
    }
}

fn current_language() -> String {
    let args: Vec<_> = env::args().collect();
    for (index, value) in args.iter().enumerate().skip(1) {
        if let Some(code) = value.strip_prefix("--language=") {
            return normalize(code);
        }
        if value == "--language" {
            if let Some(code) = args.get(index + 1) {
                return normalize(code);
            }
        }
    }
    if let Ok(code) = env::var("OMARCHY_YUBIKEY_LANGUAGE") {
        if !code.is_empty() {
            return normalize(&code);
        }
    }
    let config = env::var_os("XDG_CONFIG_HOME")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")));
    let file =
        env::var_os("OMARCHY_LANGUAGE_FILE").map(PathBuf::from).or_else(|| config.map(|p| p.join("omarchy/language")));
    if let Some(file) = file {
        if let Ok(code) = fs::read_to_string(file) {
            if !code.trim().is_empty() {
                return normalize(&code);
            }
        }
    }
    for name in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        if let Ok(code) = env::var(name) {
            if !code.is_empty() {
                return normalize(&code);
            }
        }
    }
    "en".into()
}

pub fn text(source: &str, values: &[String]) -> String {
    let template = STRINGS.get(source).and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(source);
    render(template, values)
}

fn render(template: &str, values: &[String]) -> String {
    let mut output = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '%' || !chars.peek().is_some_and(|c| ('1'..='9').contains(c)) {
            output.push(character);
            continue;
        }
        let mut digits = String::new();
        while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            digits.push(chars.next().unwrap());
        }
        match digits.parse::<usize>().ok().and_then(|n| values.get(n - 1)) {
            Some(value) => output.push_str(value),
            None => {
                output.push('%');
                output.push_str(&digits);
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regional_locales_and_aliases() {
        for (input, expected) in [
            ("de_AT.UTF-8", "de"),
            ("pt_BR.UTF-8", "pt-BR"),
            ("es_ES", "es-MX"),
            ("nb_NO", "no"),
            ("zh_HK", "zh-TW"),
            ("../de", "en"),
            ("C", "en"),
        ] {
            assert_eq!(normalize(input), expected);
        }
    }
    #[test]
    fn substitution_does_not_interpret_values() {
        let values = vec!["label %2".into(), "<b>&pass</b>".into()];
        assert_eq!(render("%2 / %1 / %10", &values), "<b>&pass</b> / label %2 / %10");
    }
}
