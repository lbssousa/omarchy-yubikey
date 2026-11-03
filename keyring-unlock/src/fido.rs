//! YubiKey über libfido2: ein Credential, das keinen Platz am Key belegt, und
//! hmac-secret nur mit Berühren, ohne FIDO2-PIN.

use anyhow::{bail, Context, Result};
use fido2_rs::assertion::AssertRequest;
use fido2_rs::credentials::{CoseType, Credential, Extensions, Opt};
use fido2_rs::device::{Device, DeviceCancel, DeviceInfo, DeviceList};
use fido2_rs::error::Error as FidoError;
use zeroize::Zeroizing;

pub const RP_ID: &str = "omarchy-yubikey.keyring-unlock";

/// `KEYRING_UNLOCK_DEBUG=1` schaltet die Protokollausgabe von libfido2 ein.
pub fn init() {
    let flags = if std::env::var_os("KEYRING_UNLOCK_DEBUG").is_some() { libfido2_sys::FIDO_DEBUG } else { 0 };
    unsafe { libfido2_sys::fido_init(flags) };
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("Zufallsquelle nicht verfügbar");
    buf
}

pub fn devices() -> Result<Vec<(DeviceInfo, Device)>> {
    let mut found = Vec::new();
    for info in DeviceList::list_devices(8).map_err(fido_error)? {
        match info.open() {
            Ok(dev) => found.push((info, dev)),
            Err(e) => eprintln!("{} lässt sich nicht öffnen: {}", info.path.to_string_lossy(), describe(&e)),
        }
    }
    Ok(found)
}

fn code(e: &FidoError) -> Option<i32> {
    match e {
        FidoError::Fido(f) => Some(f.code),
        _ => None,
    }
}

/// Der Key wurde nicht rechtzeitig berührt, oder das Warten wurde abgebrochen.
#[derive(Debug)]
pub struct NotTouched;

impl std::fmt::Display for NotTouched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key nicht rechtzeitig berührt oder abgebrochen")
    }
}

impl std::error::Error for NotTouched {}

fn not_touched(e: &FidoError) -> bool {
    matches!(code(e), Some(c) if [
        libfido2_sys::FIDO_ERR_ACTION_TIMEOUT,
        libfido2_sys::FIDO_ERR_USER_ACTION_TIMEOUT,
        libfido2_sys::FIDO_ERR_OPERATION_DENIED,
        libfido2_sys::FIDO_ERR_KEEPALIVE_CANCEL,
    ].contains(&c))
}

/// Bricht das Warten auf die Berührung ab. fido_dev_cancel ist genau dafür da, von
/// einem anderen Thread aus gerufen zu werden, während dort eine Anfrage läuft.
pub struct Cancel<'a>(DeviceCancel<'a>);

// SAFETY: fido_dev_cancel schickt nur CTAPHID_CANCEL über das offene Gerät und
// verändert nichts, was die wartende Anfrage im anderen Thread liest.
unsafe impl Send for Cancel<'_> {}
unsafe impl Sync for Cancel<'_> {}

impl<'a> Cancel<'a> {
    pub fn new(dev: &'a Device) -> Self {
        Cancel(dev.cancel_handle())
    }

    pub fn cancel(&self) {
        self.0.cancel();
    }
}

pub fn needs_pin(e: &FidoError) -> bool {
    matches!(code(e), Some(c) if c == libfido2_sys::FIDO_ERR_PIN_REQUIRED || c == libfido2_sys::FIDO_ERR_UV_INVALID)
}

pub fn describe(e: &FidoError) -> String {
    match code(e) {
        Some(c) if c == libfido2_sys::FIDO_ERR_ACTION_TIMEOUT || c == libfido2_sys::FIDO_ERR_USER_ACTION_TIMEOUT => {
            "Key nicht rechtzeitig berührt".into()
        }
        Some(c) if c == libfido2_sys::FIDO_ERR_NO_CREDENTIALS => "dieser Key ist nicht eingerichtet".into(),
        Some(c) if c == libfido2_sys::FIDO_ERR_PIN_INVALID => "FIDO2-PIN falsch".into(),
        Some(c) if c == libfido2_sys::FIDO_ERR_PIN_BLOCKED => "FIDO2-PIN gesperrt".into(),
        Some(c) if c == libfido2_sys::FIDO_ERR_OPERATION_DENIED || c == libfido2_sys::FIDO_ERR_KEEPALIVE_CANCEL => {
            "Key nicht rechtzeitig berührt oder abgebrochen".into()
        }
        Some(c) => format!("libfido2-Fehler 0x{c:02x}"),
        None => e.to_string(),
    }
}

fn fido_error(e: FidoError) -> anyhow::Error {
    anyhow::anyhow!(describe(&e))
}

/// Legt ein nicht residentes ES256-Credential mit hmac-secret an. Einmal berühren.
pub fn make_credential(dev: &Device, pin: Option<&str>) -> Result<Vec<u8>, FidoError> {
    let mut cred = Credential::new()?;
    cred.set_client_data_hash(random::<32>())?;
    cred.set_rp(RP_ID, "Schlüsselbund entsperren")?;
    cred.set_user(random::<16>(), "keyring-unlock", Some("GNOME Keyring"), None)?;
    cred.set_cose_type(CoseType::ES256)?;
    cred.set_extension(Extensions::HMAC_SECRET)?;
    dev.make_credential(&mut cred, pin)?;
    Ok(cred.id().to_vec())
}

/// Fragt ohne Berühren (up=false), welches der Credentials dieser Key kennt.
pub fn probe(dev: &Device, credential_ids: &[&[u8]]) -> Result<Option<Vec<u8>>> {
    if credential_ids.is_empty() {
        return Ok(None);
    }
    let mut req = AssertRequest::new().map_err(fido_error)?;
    req.set_rp(RP_ID).map_err(fido_error)?;
    req.set_client_data_hash(random::<32>()).map_err(fido_error)?;
    for id in credential_ids {
        req.set_allow_credential(id).map_err(fido_error)?;
    }
    req.set_up(Opt::False).map_err(fido_error)?;
    match dev.get_assertion(req, None) {
        Ok(asserts) => {
            let id = asserts.iter().next().map(|a| a.id().to_vec()).unwrap_or_default();
            // Bei nur einem erlaubten Credential darf der Key die ID weglassen.
            if id.is_empty() && credential_ids.len() == 1 {
                return Ok(Some(credential_ids[0].to_vec()));
            }
            Ok(Some(id))
        }
        Err(e) if code(&e) == Some(libfido2_sys::FIDO_ERR_NO_CREDENTIALS) => Ok(None),
        Err(e) => Err(fido_error(e)),
    }
}

/// hmac-secret für `salt`: verlangt Berühren, aber keine FIDO2-PIN (uv bleibt aus,
/// damit Einrichten und Entsperren dasselbe Geheimnis liefern).
pub fn hmac_secret(dev: &Device, credential_id: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut req = AssertRequest::new().map_err(fido_error)?;
    req.set_rp(RP_ID).map_err(fido_error)?;
    req.set_client_data_hash(random::<32>()).map_err(fido_error)?;
    req.set_allow_credential(credential_id).map_err(fido_error)?;
    req.set_up(Opt::True).map_err(fido_error)?;
    req.set_extensions(Extensions::HMAC_SECRET).map_err(fido_error)?;
    req.set_hmac_salt(salt).map_err(fido_error)?;
    let asserts = dev.get_assertion(req, None).map_err(|e| {
        if not_touched(&e) {
            anyhow::Error::new(NotTouched)
        } else {
            fido_error(e)
        }
    })?;
    let assertion = asserts.iter().next().context("Key lieferte keine Antwort")?;
    let secret = assertion.hmac_secret();
    if secret.len() != 32 {
        bail!("Key lieferte kein hmac-secret ({} Bytes)", secret.len());
    }
    Ok(Zeroizing::new(secret.to_vec()))
}
