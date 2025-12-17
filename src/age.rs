use std::{
    io::{self, Read, ErrorKind as IoErrorKind},
    path::Path,
};

use age::{
    armor::ArmoredReader,
    plugin::{self, RecipientPluginV1},
    Callbacks, DecryptError, Decryptor, Encryptor, Identity, IdentityFile, Recipient,
};
use anyhow::{bail, Context, Result};

/// Callbacks that do nothing - used when no interactive prompts are needed
#[derive(Clone)]
struct NoOpCallbacks;

impl Callbacks for NoOpCallbacks {
    fn display_message(&self, _message: &str) {}
    fn confirm(&self, _message: &str, _yes_string: &str, _no_string: Option<&str>) -> Option<bool> {
        None
    }
    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }
    fn request_passphrase(&self, _description: &str) -> Option<age::secrecy::SecretString> {
        None
    }
}

pub(crate) fn decrypt(
    identities: &[impl AsRef<Path>],
    encrypted: &mut impl Read,
) -> Result<Option<Vec<u8>>> {
    let id = load_identities(identities)?;
    let id_refs = id.iter().map(|i| i.as_ref() as &dyn Identity);
    let mut decrypted = vec![];
    let decryptor = match Decryptor::new(ArmoredReader::new(encrypted)) {
        Ok(d) => {
            if d.is_scrypt() {
                bail!("Passphrase encrypted files are not supported");
            }
            d
        }
        Err(DecryptError::InvalidHeader) => return Ok(None),
        Err(DecryptError::Io(e)) => {
            match e.kind() {
                // Age gives unexpected EOF when the file contains not enough data
                IoErrorKind::UnexpectedEof => return Ok(None),
                _ => bail!(e),
            }
        }
        Err(e) => {
            println!("Error: {:?}", e);
            bail!(e)
        }
    };

    let mut reader = decryptor.decrypt(id_refs.into_iter())?;
    reader.read_to_end(&mut decrypted)?;
    Ok(Some(decrypted))
}

fn load_identities(identities: &[impl AsRef<Path>]) -> Result<Vec<Box<dyn Identity + Send + Sync>>> {
    let mut all_identities: Vec<Box<dyn Identity + Send + Sync>> = vec![];
    
    for path in identities {
        let path = path.as_ref();
        let identity_file = IdentityFile::from_file(path.to_string_lossy().to_string())
            .with_context(|| format!("Failed to read identity file: {:?}", path))?;
        
        let file_identities = identity_file
            .with_callbacks(NoOpCallbacks)
            .into_identities()
            .with_context(|| format!("Failed to parse identities from: {:?}", path))?;
        
        all_identities.extend(file_identities);
    }
    
    Ok(all_identities)
}

pub(crate) fn encrypt(
    public_keys: &[impl AsRef<str> + std::fmt::Debug],
    cleartext: &mut impl Read,
) -> Result<Vec<u8>> {
    let recipients = load_public_keys(public_keys)?;
    let recipient_refs: Vec<&dyn Recipient> = recipients.iter().map(|r| r.as_ref() as &dyn Recipient).collect();

    let encryptor = Encryptor::with_recipients(recipient_refs.into_iter()).with_context(|| {
        format!(
            "Couldn't load keys for recepients; public_keys={:?}",
            public_keys
        )
    })?;
    let mut encrypted = vec![];

    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    io::copy(cleartext, &mut writer)?;
    writer.finish()?;
    Ok(encrypted)
}

fn load_public_keys(public_keys: &[impl AsRef<str>]) -> Result<Vec<Box<dyn Recipient + Send>>> {
    let mut recipients: Vec<Box<dyn Recipient + Send>> = vec![];
    let mut plugin_recipients = vec![];

    for pubk in public_keys {
        if let Ok(pk) = pubk.as_ref().parse::<age::x25519::Recipient>() {
            recipients.push(Box::new(pk));
        } else if let Ok(pk) = pubk.as_ref().parse::<age::ssh::Recipient>() {
            recipients.push(Box::new(pk));
        } else if let Ok(recipient) = pubk.as_ref().parse::<plugin::Recipient>() {
            plugin_recipients.push(recipient);
        } else {
            bail!("Invalid recipient");
        }
    }

    for plugin_name in plugin_recipients.iter().map(|r| r.plugin()) {
        let recipient = RecipientPluginV1::new(plugin_name, &plugin_recipients, &[], NoOpCallbacks)?;
        recipients.push(Box::new(recipient));
    }

    Ok(recipients)
}

pub(crate) fn validate_public_keys(public_keys: &[impl AsRef<str>]) -> Result<()> {
    load_public_keys(public_keys)?;
    Ok(())
}

pub(crate) fn validate_identity(identity: impl AsRef<Path>) -> Result<()> {
    let path = identity.as_ref();
    let identity_file = IdentityFile::from_file(path.to_string_lossy().to_string())
        .with_context(|| format!("Failed to read identity file: {:?}", path))?;
    
    identity_file
        .with_callbacks(NoOpCallbacks)
        .into_identities()
        .with_context(|| format!("Failed to parse identity from: {:?}", path))?;
    
    Ok(())
}
