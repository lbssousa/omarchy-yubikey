//! Encrypted keyring password storage with one entry per YubiKey.
//! Encryption keys are derived from hmac-secret and never written to disk.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const VERSION: u32 = 1;
const HKDF_INFO: &[u8] = b"keyring-unlock v1 keyring-password";

#[derive(Serialize, Deserialize)]
pub struct Store {
    pub version: u32,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub label: String,
    pub created: String,
    #[serde(with = "b64")]
    pub credential_id: Vec<u8>,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

impl Store {
    pub fn new() -> Self {
        Store { version: VERSION, entries: Vec::new() }
    }

    pub fn credential_ids(&self) -> Vec<&[u8]> {
        self.entries.iter().map(|e| e.credential_id.as_slice()).collect()
    }
}

/// Resolve `KEYRING_UNLOCK_STORE` or the default path under the XDG config directory.
pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("KEYRING_UNLOCK_STORE") {
        return Ok(PathBuf::from(p));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(base.join("keyring-unlock").join("password.json"))
}

pub fn load(path: &Path) -> Result<Store> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("No enrollment store found at {}. Run: keyring-unlock enroll", path.display())
        }
        Err(e) => return Err(e).with_context(|| format!("Could not read {}", path.display())),
    };
    let store: Store =
        serde_json::from_slice(&raw).with_context(|| format!("Invalid enrollment store JSON in {}", path.display()))?;
    if store.version != VERSION {
        bail!("{}: unsupported store version {}", path.display(), store.version);
    }
    Ok(store)
}

/// Save atomically, creating the file with mode 0600 and new directories with mode 0700.
pub fn save(path: &Path, store: &Store) -> Result<()> {
    let dir = path.parent().context("Store path has no parent directory")?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let tmp = path.with_extension("json.tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("Could not write {}", tmp.display()))?;
    file.write_all(&serde_json::to_vec_pretty(store)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn cipher(hmac_secret: &[u8]) -> Result<ChaCha20Poly1305> {
    if hmac_secret.len() != 32 {
        bail!("Invalid hmac-secret length: {} bytes; expected 32", hmac_secret.len());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, hmac_secret)
        .expand(HKDF_INFO, key.as_mut())
        .map_err(|_| anyhow::anyhow!("HKDF key derivation failed"))?;
    Ok(ChaCha20Poly1305::new(Key::from_slice(key.as_ref())))
}

/// Encrypt the password, binding the credential ID as authenticated associated data.
pub fn seal(hmac_secret: &[u8], credential_id: &[u8], password: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("Could not generate random bytes: {e}"))?;
    let ciphertext = cipher(hmac_secret)?
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: password, aad: credential_id })
        .map_err(|_| anyhow::anyhow!("Password encryption failed"))?;
    Ok((nonce.to_vec(), ciphertext))
}

pub fn open(entry: &Entry, hmac_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if entry.nonce.len() != 12 {
        bail!("Entry '{}': invalid nonce length", entry.label);
    }
    let password = cipher(hmac_secret)?
        .decrypt(Nonce::from_slice(&entry.nonce), Payload { msg: &entry.ciphertext, aad: &entry.credential_id })
        .map_err(|_| anyhow::anyhow!("Could not decrypt password (wrong key or modified enrollment store)"))?;
    Ok(Zeroizing::new(password))
}

mod b64 {
    use super::{Engine, B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        B64.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(secret: &[u8], cred: &[u8], password: &[u8]) -> Entry {
        let (nonce, ciphertext) = seal(secret, cred, password).unwrap();
        Entry {
            label: "test".into(),
            created: "2026-01-01 00:00".into(),
            credential_id: cred.to_vec(),
            salt: vec![7; 32],
            nonce,
            ciphertext,
        }
    }

    #[test]
    fn roundtrip() {
        let e = entry(&[1; 32], b"cred", b"123456");
        assert_eq!(open(&e, &[1; 32]).unwrap().as_slice(), b"123456");
        assert!(!e.ciphertext.windows(6).any(|w| w == b"123456"));
    }

    #[test]
    fn wrong_secret_fails() {
        let e = entry(&[1; 32], b"cred", b"123456");
        assert!(open(&e, &[2; 32]).is_err());
    }

    #[test]
    fn swapped_credential_fails() {
        let mut e = entry(&[1; 32], b"cred", b"123456");
        e.credential_id = b"other".to_vec();
        assert!(open(&e, &[1; 32]).is_err());
    }

    #[test]
    fn short_secret_rejected() {
        assert!(seal(&[1; 16], b"cred", b"123456").is_err());
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join(format!("keyring-unlock-test-{}", std::process::id()));
        let path = dir.join("password.json");
        let mut store = Store::new();
        store.entries.push(entry(&[3; 32], b"cred", b"654321"));
        save(&path, &store).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions());
        let loaded = load(&path).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(open(&loaded.entries[0], &[3; 32]).unwrap().as_slice(), b"654321");
    }
}
