//! GNOME Keyring access over D-Bus. Unlike `gnome-keyring-daemon --unlock`,
//! which targets the login keyring, `UnlockWithMasterPassword` accepts any collection.

use anyhow::{Context, Result};
use std::collections::HashMap;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const DEST: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const GNOME: &str = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface";

pub struct Keyring {
    conn: Connection,
}

pub struct Collection {
    pub path: OwnedObjectPath,
    pub label: String,
}

/// An item and its secret, suitable for copying to another collection.
pub struct Item {
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
}

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

impl Keyring {
    /// Connect to the user session bus; service calls can activate the keyring daemon.
    pub fn connect() -> Result<Self> {
        let conn = Connection::session().context("Could not connect to the session bus")?;
        Ok(Keyring { conn })
    }

    fn proxy<'a>(&'a self, path: &'a str, iface: &'a str) -> Result<Proxy<'a>> {
        Proxy::new(&self.conn, DEST, path, iface).context("Could not connect to Secret Service")
    }

    /// Resolve the default collection used by browsers to store secrets.
    pub fn default_collection(&self) -> Result<Collection> {
        let path: OwnedObjectPath =
            self.proxy(SERVICE_PATH, SERVICE)?.call("ReadAlias", &("default",)).context("ReadAlias(default) failed")?;
        if path.as_str() == "/" {
            anyhow::bail!("No default keyring is configured");
        }
        self.collection(path)
    }

    /// List persistent collections, excluding the transient session collection.
    pub fn collections(&self) -> Result<Vec<Collection>> {
        let paths: Vec<OwnedObjectPath> = self.proxy(SERVICE_PATH, SERVICE)?.get_property("Collections")?;
        paths.into_iter().filter(|p| !p.as_str().ends_with("/session")).map(|p| self.collection(p)).collect()
    }

    fn collection(&self, path: OwnedObjectPath) -> Result<Collection> {
        let label: String = self.proxy(path.as_str(), COLLECTION)?.get_property("Label")?;
        Ok(Collection { path, label })
    }

    pub fn locked(&self, collection: &Collection) -> Result<bool> {
        Ok(self.proxy(collection.path.as_str(), COLLECTION)?.get_property("Locked")?)
    }

    pub fn lock(&self, collection: &Collection) -> Result<()> {
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = self
            .proxy(SERVICE_PATH, SERVICE)?
            .call("Lock", &(vec![ObjectPath::from(&collection.path)],))
            .with_context(|| format!("Could not lock keyring '{}'", collection.label))?;
        if prompt.as_str() != "/" || !self.locked(collection)? {
            anyhow::bail!("Keyring '{}' did not lock", collection.label);
        }
        Ok(())
    }

    /// Use a plain Secret Service session: secrets are not encrypted on the
    /// session bus and rely on its per-user access controls.
    fn with_session<T>(&self, run: impl FnOnce(&OwnedObjectPath) -> Result<T>) -> Result<T> {
        let (_, session): (OwnedValue, OwnedObjectPath) = self
            .proxy(SERVICE_PATH, SERVICE)?
            .call("OpenSession", &("plain", Value::from("")))
            .context("OpenSession failed")?;
        let result = run(&session);
        let _: zbus::Result<()> = self.proxy(session.as_str(), "org.freedesktop.Secret.Session")?.call("Close", &());
        result
    }

    /// Unlock a collection using its password.
    pub fn unlock(&self, collection: &Collection, password: &[u8]) -> Result<()> {
        self.with_session(|session| {
            let master = (ObjectPath::from(session), Vec::<u8>::new(), password, "text/plain");
            let result: zbus::Result<()> = self
                .proxy(SERVICE_PATH, GNOME)?
                .call("UnlockWithMasterPassword", &(ObjectPath::from(&collection.path), master));
            result.with_context(|| format!("Could not unlock keyring '{}' (check the password)", collection.label))
        })
    }

    /// Read all items and their secrets from an unlocked collection.
    pub fn items(&self, collection: &Collection) -> Result<Vec<Item>> {
        let paths: Vec<OwnedObjectPath> = self.proxy(collection.path.as_str(), COLLECTION)?.get_property("Items")?;
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let secrets: HashMap<OwnedObjectPath, Secret> = self.with_session(|session| {
            Ok(self
                .proxy(SERVICE_PATH, SERVICE)?
                .call("GetSecrets", &(&paths, ObjectPath::from(session)))
                .with_context(|| format!("Could not read secrets from keyring '{}'", collection.label))?)
        })?;
        let mut items = Vec::new();
        for path in paths {
            let item = self.proxy(path.as_str(), ITEM)?;
            let (_, _, value, content_type) =
                secrets.get(&path).with_context(|| format!("No secret returned for {}", path.as_str()))?.clone();
            items.push(Item {
                label: item.get_property("Label")?,
                attributes: item.get_property("Attributes")?,
                secret: Zeroizing::new(value),
                content_type,
            });
        }
        Ok(items)
    }

    /// Check whether a collection contains an item with exactly these attributes.
    pub fn contains(&self, collection: &Collection, attributes: &HashMap<String, String>) -> Result<bool> {
        if attributes.is_empty() {
            return Ok(false);
        }
        let found: Vec<OwnedObjectPath> =
            self.proxy(collection.path.as_str(), COLLECTION)?.call("SearchItems", &(attributes,))?;
        for path in found {
            let existing: HashMap<String, String> = self.proxy(path.as_str(), ITEM)?.get_property("Attributes")?;
            if existing == *attributes {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn add(&self, collection: &Collection, item: &Item) -> Result<()> {
        self.with_session(|session| {
            let properties = HashMap::from([
                ("org.freedesktop.Secret.Item.Label", Value::from(item.label.as_str())),
                ("org.freedesktop.Secret.Item.Attributes", Value::from(item.attributes.clone())),
            ]);
            let secret =
                (ObjectPath::from(session), Vec::<u8>::new(), item.secret.as_slice(), item.content_type.as_str());
            let _: (OwnedObjectPath, OwnedObjectPath) = self
                .proxy(collection.path.as_str(), COLLECTION)?
                .call("CreateItem", &(properties, secret, false))
                .with_context(|| format!("Could not copy item '{}'", item.label))?;
            Ok(())
        })
    }

    /// Delete a collection only if the daemon does not require an interactive prompt.
    pub fn delete(&self, collection: &Collection) -> Result<()> {
        let prompt: OwnedObjectPath = self
            .proxy(collection.path.as_str(), COLLECTION)?
            .call("Delete", &())
            .with_context(|| format!("Could not delete keyring '{}'", collection.label))?;
        if prompt.as_str() != "/" {
            anyhow::bail!("Keyring '{}': deletion requires confirmation; collection was not deleted", collection.label);
        }
        Ok(())
    }
}
