//! Autologin provides no password to PAM, so GNOME Keyring remains locked.
//! This helper encrypts the keyring password using a YubiKey hmac-secret and
//! unlocks collections over D-Bus after a key touch. The normal password prompt
//! remains available when the key is absent or the touch is cancelled.

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
#[command(version, about = "Unlock GNOME Keyring with a YubiKey touch")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Unlock keyrings that share the enrolled password (default command)
    Unlock,
    /// Encrypt the keyring password for all connected supported keys
    Enroll {
        /// Keep existing entries and enroll only keys not already in the store
        #[arg(long)]
        add: bool,
        /// Label for the enrollment entry, such as "Primary key"
        #[arg(long)]
        label: Option<String>,
        /// Read the password from the first line of stdin instead of prompting
        #[arg(long)]
        password_stdin: bool,
    },
    /// Copy items into the default keyring, then delete the source keyrings
    Merge,
    /// Verify password decryption with a key touch without unlocking keyrings
    Check,
    /// Show enrollment entries, connected keys and keyrings without a key touch
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
        eprintln!("Keyring '{}' is already unlocked", default.label);
        return Ok(());
    }
    let store = store::load(&store::path()?)?;
    let (dev, entry) = match enrolled_key(&store) {
        Ok(found) => found,
        Err(e) => {
            // A missing enrolled key is not a service failure; leave the password prompt available.
            eprintln!("{e:#}; use the normal password prompt");
            return Ok(());
        }
    };

    let toast = notify("Touch your YubiKey", "to unlock GNOME Keyring", "normal", 30_000);
    // Cancel the pending key touch if the user unlocks the keyring through the password prompt.
    let password = decrypt_unless(&dev, entry, || keyring.locked(&default).map_or(false, |locked| !locked));
    if let Some(id) = toast {
        close_notification(id);
    }
    let password = match password {
        Ok(Some(password)) => password,
        Ok(None) => {
            eprintln!("Keyring unlocked through the password prompt; key touch cancelled");
            return Ok(());
        }
        Err(e) if e.downcast_ref::<fido::NotTouched>().is_some() => {
            eprintln!("Key touch timed out or was cancelled; use the normal password prompt");
            return Ok(());
        }
        Err(e) => {
            notify("Could not unlock keyring", &format!("{e:#}"), "normal", 8000);
            return Err(e);
        }
    };

    if let Err(e) = keyring.unlock(&default, &password) {
        notify("Could not unlock keyring", &format!("{e:#}"), "normal", 8000);
        return Err(e);
    }
    eprintln!("Keyring '{}' unlocked", default.label);
    // Also attempt other locked keyrings with the same password.
    for other in keyring.collections()? {
        if other.path == default.path || !keyring.locked(&other)? {
            continue;
        }
        match keyring.unlock(&other, &password) {
            Ok(()) => eprintln!("Keyring '{}' ({}) unlocked", other.label, other.path.as_str()),
            Err(e) => eprintln!("{e:#}"),
        }
    }
    Ok(())
}

fn check() -> Result<()> {
    let store = store::load(&store::path()?)?;
    let (dev, entry) = enrolled_key(&store)?;
    eprintln!("Touch your YubiKey...");
    let secret = fido::hmac_secret(&dev, &entry.credential_id, &entry.salt)?;
    let password = store::open(entry, &secret)?;
    println!("OK: Decrypted a {}-byte password; no keyrings were unlocked.", password.len());
    Ok(())
}

/// Find a connected key that recognizes a stored credential without requiring a touch.
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
            store.entries.iter().find(|e| e.credential_id == id).context("Key returned an unknown credential")?;
        return Ok((dev, entry));
    }
    match last_error {
        Some(e) => Err(e),
        None => bail!("No enrolled YubiKey is connected"),
    }
}

/// Wait for a key touch, polling `give_up` every 300 ms.
/// Return `None` if the pending request is cancelled by `give_up`.
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

    // Validate the password by locking and unlocking the default keyring before
    // storing it, so an incorrect password cannot be enrolled.
    let keyring = Keyring::connect()?;
    let default = keyring.default_collection()?;
    keyring.lock(&default)?;
    keyring.unlock(&default, password.as_bytes()).context(
        "Password validation failed; the keyring remains locked (use the normal password prompt to unlock it)",
    )?;
    eprintln!("Password verified; keyring '{}' is unlocked", default.label);

    let entries = seal_for_keys(&store, add, label.as_deref(), password.as_bytes())?;
    let added = entries.len();
    store.entries.extend(entries);
    if added == 0 {
        bail!("No new keys were enrolled");
    }
    store::save(&path, &store)?;
    println!("Enrolled {} key(s); store saved to {}", added, path.display());
    Ok(())
}

/// Encrypt the password for each connected key, requiring two touches per key.
/// When `skip_known` is set, skip keys already enrolled in `store`.
fn seal_for_keys(store: &Store, skip_known: bool, label: Option<&str>, password: &[u8]) -> Result<Vec<Entry>> {
    let devices = fido::devices()?;
    if devices.is_empty() {
        bail!("No FIDO2 key is connected");
    }
    let known: Vec<Vec<u8>> = store.credential_ids().into_iter().map(<[u8]>::to_vec).collect();
    let known: Vec<&[u8]> = known.iter().map(Vec::as_slice).collect();
    let created = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    let mut entries = Vec::new();

    for (n, (info, dev)) in devices.iter().enumerate() {
        let name = format!("{} ({})", info.product.to_string_lossy(), info.path.to_string_lossy());
        if skip_known && fido::probe(dev, &known)?.is_some() {
            eprintln!("{name}: already enrolled; skipping");
            continue;
        }
        eprintln!("{name}: touch the key (1/2)...");
        let credential_id = match fido::make_credential(dev, None) {
            Ok(id) => id,
            Err(e) if fido::needs_pin(&e) => {
                let key_pin = Zeroizing::new(rpassword::prompt_password(
                    "Enter the key's FIDO2 PIN (not the keyring password): ",
                )?);
                eprintln!("{name}: touch the key (1/2)...");
                fido::make_credential(dev, Some(&key_pin)).map_err(|e| anyhow::anyhow!(fido::describe(&e)))?
            }
            Err(e) => bail!("{name}: {}", fido::describe(&e)),
        };
        eprintln!("{name}: touch the key again (2/2)...");
        let salt = fido::random::<32>().to_vec();
        let secret = fido::hmac_secret(dev, &credential_id, &salt)?;
        let (nonce, ciphertext) = store::seal(&secret, &credential_id, password)?;
        let label = match (label, n) {
            (Some(label), 0) => label.to_string(),
            (Some(label), n) => format!("{label} {}", n + 1),
            (None, _) => name.clone(),
        };
        entries.push(Entry { label, created: created.clone(), credential_id, salt, nonce, ciphertext });
        eprintln!("{name}: enrolled");
    }
    Ok(entries)
}

/// Copy items from other keyrings into the default collection, preserving
/// existing items with identical attributes. Delete source collections only
/// after copying succeeds and items with nonempty attributes are verified.
fn merge() -> Result<()> {
    let keyring = Keyring::connect()?;
    let target = keyring.default_collection()?;
    let sources: Vec<_> = keyring.collections()?.into_iter().filter(|c| c.path != target.path).collect();
    if sources.is_empty() {
        println!("Only keyring '{}' exists; nothing to merge", target.label);
        return Ok(());
    }
    let locked: Vec<String> = std::iter::once(&target)
        .chain(&sources)
        .filter(|c| keyring.locked(c).unwrap_or(true))
        .map(|c| format!("'{}' ({})", c.label, c.path.as_str()))
        .collect();
    if !locked.is_empty() {
        bail!("Unlock these keyrings first: {}", locked.join(", "));
    }

    for source in &sources {
        let (mut copied, mut skipped) = (0, 0);
        let items = keyring.items(source)?;
        for item in &items {
            if keyring.contains(&target, &item.attributes)? {
                eprintln!("Item '{}': already present in the default keyring; skipping", item.label);
                skipped += 1;
                continue;
            }
            keyring.add(&target, item)?;
            copied += 1;
        }
        // Verify items with nonempty attributes before deleting the source collection.
        for item in &items {
            if !item.attributes.is_empty() && !keyring.contains(&target, &item.attributes)? {
                bail!(
                    "Item '{}' is missing from keyring '{}'; keeping {}",
                    item.label,
                    target.label,
                    source.path.as_str()
                );
            }
        }
        keyring.delete(source)?;
        println!(
            "{} -> {}: {copied} copied, {skipped} duplicates skipped; source keyring deleted",
            source.path.as_str(),
            target.path.as_str()
        );
    }
    Ok(())
}

fn status() -> Result<()> {
    let path = store::path()?;
    let store = store::load(&path)?;
    println!("Store: {}", path.display());
    for entry in &store.entries {
        println!("  {}  (enrolled {})", entry.label, entry.created);
    }
    let ids = store.credential_ids();
    let devices = fido::devices()?;
    if devices.is_empty() {
        println!("Connected: no FIDO2 key");
    }
    for (info, dev) in devices {
        let state = match fido::probe(&dev, &ids)? {
            Some(id) => match store.entries.iter().find(|e| e.credential_id == id) {
                Some(entry) => format!("enrolled as '{}'", entry.label),
                None => "returned an unknown credential".into(),
            },
            None => "not enrolled".into(),
        };
        println!("Connected: {} ({}): {state}", info.product.to_string_lossy(), info.path.to_string_lossy());
    }
    let keyring = Keyring::connect()?;
    let default = keyring.default_collection()?;
    for collection in keyring.collections()? {
        let state = if keyring.locked(&collection)? { "locked" } else { "unlocked" };
        let mark = if collection.path == default.path { " (default)" } else { "" };
        println!("Keyring: '{}'{mark} {}: {state}", collection.label, collection.path.as_str());
    }
    Ok(())
}

fn read_password(from_stdin: bool) -> Result<Zeroizing<String>> {
    let password = if from_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string())
    } else {
        let first = Zeroizing::new(rpassword::prompt_password("Keyring password: ")?);
        let second = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        if *first != *second {
            bail!("Passwords do not match");
        }
        first
    };
    if password.is_empty() {
        bail!("The keyring password is empty; key-based unlock is unnecessary");
    }
    Ok(password)
}

fn single_instance() -> Result<Option<File>> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR is not set")?;
    let file = File::create(Path::new(&dir).join("keyring-unlock.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// Send an Omarchy notification, bypassing Do Not Disturb, and return its ID for dismissal.
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
