//! Autologin gibt PAM kein Passwort, also bleibt gnome-keyring nach dem Anmelden
//! zu, und Chromium wartet auf die Passwortabfrage. keyring-unlock legt das
//! Schlüsselbund-Passwort mit dem hmac-secret eines YubiKeys verschlüsselt ab und
//! entsperrt nach einer Berührung des Keys über D-Bus. Ohne Key bleibt die
//! normale Abfrage.

mod fido;
mod keyring;
mod store;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use keyring::Keyring;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;
use store::{Entry, Store};
use zeroize::Zeroizing;

const GLYPH: &str = "󰌆";

#[derive(Parser)]
#[command(version, about = "GNOME-Schlüsselbund per YubiKey-Berührung entsperren")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Key berühren und alle gesperrten Schlüsselbünde entsperren (Standard ohne Befehl)
    Unlock,
    /// Schlüsselbund-Passwort für alle gesteckten Keys verschlüsselt ablegen
    Enroll {
        /// Bestehende Einträge behalten und nur noch nicht eingerichtete Keys ergänzen
        #[arg(long)]
        add: bool,
        /// Name für den Eintrag, etwa „5C Nano“
        #[arg(long)]
        label: Option<String>,
        /// Passwort aus der ersten Zeile von stdin lesen statt nachzufragen
        #[arg(long)]
        password_stdin: bool,
    },
    /// Alle übrigen Schlüsselbünde in den Standard übernehmen und danach löschen
    Merge,
    /// Key berühren und nur prüfen, ob das Passwort sich entschlüsseln lässt
    Check,
    /// Einträge, gesteckte Keys und Schlüsselbünde anzeigen (ohne Berühren)
    Status,
}

fn main() {
    let cli = Cli::parse();
    fido::init();
    let result = match cli.command.unwrap_or(Cmd::Unlock) {
        Cmd::Unlock => unlock(),
        Cmd::Enroll { add, label, password_stdin } => enroll(add, label, password_stdin),
        Cmd::Merge => merge(),
        Cmd::Check => check(),
        Cmd::Status => status(),
    };
    if let Err(e) = result {
        eprintln!("keyring-unlock: {e:#}");
        std::process::exit(1);
    }
}

fn unlock() -> Result<()> {
    let Some(_lock) = single_instance()? else { return Ok(()) };
    let keyring = Keyring::connect()?;
    let default = keyring.default_collection()?;
    if !keyring.locked(&default)? {
        eprintln!("„{}“ ist schon entsperrt", default.label);
        return Ok(());
    }
    let store = store::load(&store::path()?)?;
    let (dev, entry) = match enrolled_key(&store) {
        Ok(found) => found,
        Err(e) => {
            // Kein Fehler für den Dienst: Dann kommt eben die normale Passwortabfrage.
            eprintln!("{e:#}, bleibt bei der Passwortabfrage");
            return Ok(());
        }
    };

    let toast = notify("YubiKey berühren", "zum Entsperren des Schlüsselbunds", "normal", 30_000);
    // Tippt man das Passwort derweil selbst in die Abfrage, hört der Key auf zu blinken.
    let password = decrypt_unless(&dev, entry, || keyring.locked(&default).map_or(false, |locked| !locked));
    if let Some(id) = toast {
        close_notification(id);
    }
    let password = match password {
        Ok(Some(password)) => password,
        Ok(None) => {
            eprintln!("Schlüsselbund von Hand entsperrt, Key nicht mehr gebraucht");
            return Ok(());
        }
        Err(e) if e.downcast_ref::<fido::NotTouched>().is_some() => {
            eprintln!("Key nicht berührt, bleibt bei der Passwortabfrage");
            return Ok(());
        }
        Err(e) => {
            notify("Schlüsselbund nicht entsperrt", &format!("{e:#}"), "normal", 8000);
            return Err(e);
        }
    };

    if let Err(e) = keyring.unlock(&default, &password) {
        notify("Schlüsselbund nicht entsperrt", &format!("{e:#}"), "normal", 8000);
        return Err(e);
    }
    eprintln!("„{}“ entsperrt", default.label);
    // Weitere Schlüsselbünde mit demselben Passwort gleich mit; andere bleiben zu.
    for other in keyring.collections()? {
        if other.path == default.path || !keyring.locked(&other)? {
            continue;
        }
        match keyring.unlock(&other, &password) {
            Ok(()) => eprintln!("„{}“ ({}) entsperrt", other.label, other.path.as_str()),
            Err(e) => eprintln!("{e:#}"),
        }
    }
    Ok(())
}

fn check() -> Result<()> {
    let store = store::load(&store::path()?)?;
    let (dev, entry) = enrolled_key(&store)?;
    eprintln!("YubiKey berühren …");
    let secret = fido::hmac_secret(&dev, &entry.credential_id, &entry.salt)?;
    let password = store::open(entry, &secret)?;
    println!("Ok: Passwort mit {} Zeichen entschlüsselt, nichts entsperrt.", password.len());
    Ok(())
}

/// Sucht den gesteckten Key, der einen Eintrag kennt (ohne Berühren).
fn enrolled_key(store: &Store) -> Result<(fido2_rs::device::Device, &Entry)> {
    let ids = store.credential_ids();
    let mut last_error = None;
    for (info, dev) in fido::devices()? {
        let id = match fido::probe(&dev, &ids) {
            Ok(Some(id)) => id,
            Ok(None) => continue,
            Err(e) => {
                last_error = Some(e.context(info.path.to_string_lossy().into_owned()));
                continue;
            }
        };
        let entry =
            store.entries.iter().find(|e| e.credential_id == id).context("Key meldet ein unbekanntes Credential")?;
        return Ok((dev, entry));
    }
    match last_error {
        Some(e) => Err(e),
        None => bail!("Kein eingerichteter YubiKey gesteckt"),
    }
}

/// Wartet auf die Berührung, gibt aber auf, sobald `give_up` wahr wird (alle
/// 300 ms gefragt). Dann None.
fn decrypt_unless(
    dev: &fido2_rs::device::Device,
    entry: &Entry,
    give_up: impl Fn() -> bool + Sync,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let cancel = fido::Cancel::new(dev);
    let waiting = AtomicBool::new(true);
    let gave_up = AtomicBool::new(false);
    let secret = std::thread::scope(|s| {
        s.spawn(|| {
            while waiting.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(300));
                if waiting.load(Ordering::Relaxed) && give_up() {
                    gave_up.store(true, Ordering::Relaxed);
                    cancel.cancel();
                    return;
                }
            }
        });
        let secret = fido::hmac_secret(dev, &entry.credential_id, &entry.salt);
        waiting.store(false, Ordering::Relaxed);
        secret
    });
    if gave_up.load(Ordering::Relaxed) {
        return Ok(None);
    }
    Ok(Some(store::open(entry, &secret?)?))
}

fn enroll(add: bool, label: Option<String>, password_stdin: bool) -> Result<()> {
    let path = store::path()?;
    let mut store = if add { store::load(&path)? } else { Store::new() };
    let password = read_password(password_stdin)?;

    // Sperren und mit der Eingabe wieder entsperren prüft das Passwort; ein
    // Tippfehler landete sonst verschlüsselt in der Ablage.
    let keyring = Keyring::connect()?;
    let default = keyring.default_collection()?;
    keyring.lock(&default)?;
    keyring
        .unlock(&default, password.as_bytes())
        .context("Passwort falsch, der Schlüsselbund bleibt gesperrt (entsperren über die normale Abfrage)")?;
    eprintln!("Passwort stimmt, „{}“ ist entsperrt", default.label);

    let entries = seal_for_keys(&store, add, label.as_deref(), password.as_bytes())?;
    let added = entries.len();
    store.entries.extend(entries);
    if added == 0 {
        bail!("Nichts Neues eingerichtet");
    }
    store::save(&path, &store)?;
    println!("{} Key(s) eingerichtet, gespeichert in {}", added, path.display());
    Ok(())
}

/// Verschlüsselt das Passwort für jeden gesteckten Key (je zweimal berühren). Mit
/// `skip_known` bleiben Keys aus `store` außen vor.
fn seal_for_keys(store: &Store, skip_known: bool, label: Option<&str>, password: &[u8]) -> Result<Vec<Entry>> {
    let devices = fido::devices()?;
    if devices.is_empty() {
        bail!("Kein FIDO2-Key gesteckt");
    }
    let known: Vec<Vec<u8>> = store.credential_ids().into_iter().map(<[u8]>::to_vec).collect();
    let known: Vec<&[u8]> = known.iter().map(Vec::as_slice).collect();
    let created = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    let mut entries = Vec::new();

    for (n, (info, dev)) in devices.iter().enumerate() {
        let name = format!("{} ({})", info.product.to_string_lossy(), info.path.to_string_lossy());
        if skip_known && fido::probe(dev, &known)?.is_some() {
            eprintln!("{name}: schon eingerichtet, übersprungen");
            continue;
        }
        eprintln!("{name}: Key berühren (1/2) …");
        let credential_id = match fido::make_credential(dev, None) {
            Ok(id) => id,
            Err(e) if fido::needs_pin(&e) => {
                let key_pin = Zeroizing::new(rpassword::prompt_password(
                    "Der Key verlangt seine FIDO2-PIN (nicht das Schlüsselbund-Passwort): ",
                )?);
                eprintln!("{name}: Key berühren (1/2) …");
                fido::make_credential(dev, Some(&key_pin)).map_err(|e| anyhow::anyhow!(fido::describe(&e)))?
            }
            Err(e) => bail!("{name}: {}", fido::describe(&e)),
        };
        eprintln!("{name}: noch einmal berühren (2/2) …");
        let salt = fido::random::<32>().to_vec();
        let secret = fido::hmac_secret(dev, &credential_id, &salt)?;
        let (nonce, ciphertext) = store::seal(&secret, &credential_id, password)?;
        let label = match (label, n) {
            (Some(label), 0) => label.to_string(),
            (Some(label), n) => format!("{label} {}", n + 1),
            (None, _) => name.clone(),
        };
        entries.push(Entry { label, created: created.clone(), credential_id, salt, nonce, ciphertext });
        eprintln!("{name}: eingerichtet");
    }
    Ok(entries)
}

/// Kopiert die Einträge der anderen Schlüsselbünde in den Standard; bei gleichen
/// Attributen bleibt der des Standards. Gelöscht wird erst, wenn alles drüben ist.
fn merge() -> Result<()> {
    let keyring = Keyring::connect()?;
    let target = keyring.default_collection()?;
    let sources: Vec<_> = keyring.collections()?.into_iter().filter(|c| c.path != target.path).collect();
    if sources.is_empty() {
        println!("Nur „{}“ vorhanden, nichts zusammenzulegen", target.label);
        return Ok(());
    }
    let locked: Vec<String> = std::iter::once(&target)
        .chain(&sources)
        .filter(|c| keyring.locked(c).unwrap_or(true))
        .map(|c| format!("„{}“ ({})", c.label, c.path.as_str()))
        .collect();
    if !locked.is_empty() {
        bail!("Erst entsperren: {}", locked.join(", "));
    }

    for source in &sources {
        let (mut copied, mut skipped) = (0, 0);
        let items = keyring.items(source)?;
        for item in &items {
            if keyring.contains(&target, &item.attributes)? {
                eprintln!("„{}“: im Standard schon vorhanden, übersprungen", item.label);
                skipped += 1;
                continue;
            }
            keyring.add(&target, item)?;
            copied += 1;
        }
        // Nur löschen, was nachweislich drüben ist.
        for item in &items {
            if !item.attributes.is_empty() && !keyring.contains(&target, &item.attributes)? {
                bail!("„{}“ fehlt in „{}“, {} bleibt", item.label, target.label, source.path.as_str());
            }
        }
        keyring.delete(source)?;
        println!(
            "{} → {}: {copied} übernommen, {skipped} doppelt, alter Schlüsselbund gelöscht",
            source.path.as_str(),
            target.path.as_str()
        );
    }
    Ok(())
}

fn status() -> Result<()> {
    let path = store::path()?;
    let store = store::load(&path)?;
    println!("Ablage: {}", path.display());
    for entry in &store.entries {
        println!("  {}  (eingerichtet {})", entry.label, entry.created);
    }
    let ids = store.credential_ids();
    let devices = fido::devices()?;
    if devices.is_empty() {
        println!("Gesteckt: kein FIDO2-Key");
    }
    for (info, dev) in devices {
        let state = match fido::probe(&dev, &ids)? {
            Some(id) => match store.entries.iter().find(|e| e.credential_id == id) {
                Some(entry) => format!("eingerichtet als „{}“", entry.label),
                None => "kennt ein unbekanntes Credential".into(),
            },
            None => "nicht eingerichtet".into(),
        };
        println!("Gesteckt: {} ({}): {state}", info.product.to_string_lossy(), info.path.to_string_lossy());
    }
    let keyring = Keyring::connect()?;
    let default = keyring.default_collection()?;
    for collection in keyring.collections()? {
        let state = if keyring.locked(&collection)? { "gesperrt" } else { "entsperrt" };
        let mark = if collection.path == default.path { " (Standard)" } else { "" };
        println!("Schlüsselbund: „{}“{mark} {}: {state}", collection.label, collection.path.as_str());
    }
    Ok(())
}

fn read_password(from_stdin: bool) -> Result<Zeroizing<String>> {
    let password = if from_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string())
    } else {
        let first = Zeroizing::new(rpassword::prompt_password("Schlüsselbund-Passwort: ")?);
        let second = Zeroizing::new(rpassword::prompt_password("Noch einmal: ")?);
        if *first != *second {
            bail!("Die beiden Eingaben stimmen nicht überein");
        }
        first
    };
    if password.is_empty() {
        bail!("Leeres Passwort: Dann braucht es keinen Key");
    }
    Ok(password)
}

fn single_instance() -> Result<Option<File>> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR ist nicht gesetzt")?;
    let file = File::create(Path::new(&dir).join("keyring-unlock.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// omarchy-notification-send umgeht „Nicht stören“; gibt die ID zum Schließen zurück.
fn notify(headline: &str, body: &str, urgency: &str, timeout_ms: u32) -> Option<u32> {
    let out = Command::new("omarchy-notification-send")
        .args(["-g", GLYPH, "-u", urgency, "-t", &timeout_ms.to_string(), "-p", headline, body])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn close_notification(id: u32) {
    let _ = Command::new("busctl")
        .args([
            "--user",
            "call",
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "CloseNotification",
            "u",
            &id.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
