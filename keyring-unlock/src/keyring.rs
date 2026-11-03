//! gnome-keyring über D-Bus. `gnome-keyring-daemon --unlock` entsperrt nur einen
//! Schlüsselbund namens „login“; UnlockWithMasterPassword nimmt jeden.

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

/// Ein Eintrag samt Geheimnis, wie er sich in einen anderen Schlüsselbund kopieren lässt.
pub struct Item {
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
}

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

impl Keyring {
    /// Startet den Daemon notfalls über D-Bus-Aktivierung.
    pub fn connect() -> Result<Self> {
        let conn = Connection::session().context("Session-Bus nicht erreichbar")?;
        Ok(Keyring { conn })
    }

    fn proxy<'a>(&'a self, path: &'a str, iface: &'a str) -> Result<Proxy<'a>> {
        Proxy::new(&self.conn, DEST, path, iface).context("Secret Service nicht erreichbar")
    }

    /// Der Schlüsselbund hinter dem Alias „default“, in den Browser speichern.
    pub fn default_collection(&self) -> Result<Collection> {
        let path: OwnedObjectPath = self
            .proxy(SERVICE_PATH, SERVICE)?
            .call("ReadAlias", &("default",))
            .context("ReadAlias(default) fehlgeschlagen")?;
        if path.as_str() == "/" {
            anyhow::bail!("Kein Standard-Schlüsselbund eingerichtet");
        }
        self.collection(path)
    }

    /// Alle dauerhaften Schlüsselbünde, ohne den flüchtigen „session“.
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
            .with_context(|| format!("„{}“ nicht gesperrt", collection.label))?;
        if prompt.as_str() != "/" || !self.locked(collection)? {
            anyhow::bail!("„{}“ ließ sich nicht sperren", collection.label);
        }
        Ok(())
    }

    /// Über eine „plain“-Sitzung: Geheimnisse gehen unverschlüsselt über den
    /// Session-Bus, den nur dieser Benutzer erreicht.
    fn with_session<T>(&self, run: impl FnOnce(&OwnedObjectPath) -> Result<T>) -> Result<T> {
        let (_, session): (OwnedValue, OwnedObjectPath) = self
            .proxy(SERVICE_PATH, SERVICE)?
            .call("OpenSession", &("plain", Value::from("")))
            .context("OpenSession fehlgeschlagen")?;
        let result = run(&session);
        let _: zbus::Result<()> = self.proxy(session.as_str(), "org.freedesktop.Secret.Session")?.call("Close", &());
        result
    }

    /// Entsperrt mit dem Passwort.
    pub fn unlock(&self, collection: &Collection, password: &[u8]) -> Result<()> {
        self.with_session(|session| {
            let master = (ObjectPath::from(session), Vec::<u8>::new(), password, "text/plain");
            let result: zbus::Result<()> = self
                .proxy(SERVICE_PATH, GNOME)?
                .call("UnlockWithMasterPassword", &(ObjectPath::from(&collection.path), master));
            result.with_context(|| format!("„{}“ nicht entsperrt (Passwort falsch?)", collection.label))
        })
    }

    /// Alle Einträge mit Geheimnis; der Schlüsselbund muss entsperrt sein.
    pub fn items(&self, collection: &Collection) -> Result<Vec<Item>> {
        let paths: Vec<OwnedObjectPath> = self.proxy(collection.path.as_str(), COLLECTION)?.get_property("Items")?;
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let secrets: HashMap<OwnedObjectPath, Secret> = self.with_session(|session| {
            Ok(self
                .proxy(SERVICE_PATH, SERVICE)?
                .call("GetSecrets", &(&paths, ObjectPath::from(session)))
                .with_context(|| format!("Geheimnisse aus „{}“ nicht lesbar", collection.label))?)
        })?;
        let mut items = Vec::new();
        for path in paths {
            let item = self.proxy(path.as_str(), ITEM)?;
            let (_, _, value, content_type) =
                secrets.get(&path).with_context(|| format!("{} ohne Geheimnis", path.as_str()))?.clone();
            items.push(Item {
                label: item.get_property("Label")?,
                attributes: item.get_property("Attributes")?,
                secret: Zeroizing::new(value),
                content_type,
            });
        }
        Ok(items)
    }

    /// Gibt es dort schon einen Eintrag mit genau diesen Attributen?
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
                .with_context(|| format!("„{}“ nicht kopiert", item.label))?;
            Ok(())
        })
    }

    /// Löscht ohne Rückfrage; verlangt der Daemon eine, bleibt der Schlüsselbund.
    pub fn delete(&self, collection: &Collection) -> Result<()> {
        let prompt: OwnedObjectPath = self
            .proxy(collection.path.as_str(), COLLECTION)?
            .call("Delete", &())
            .with_context(|| format!("„{}“ nicht gelöscht", collection.label))?;
        if prompt.as_str() != "/" {
            anyhow::bail!("„{}“: Löschen verlangt eine Rückfrage, nicht gelöscht", collection.label);
        }
        Ok(())
    }
}
