use std::{
    env,
    fs::File,
    io::{self, BufReader, Read, ErrorKind as IoErrorKind},
    path::Path,
};

use age::{
    armor::ArmoredReader,
    plugin::{self, RecipientPluginV1},
    Callbacks, DecryptError, Decryptor, Encryptor, Identity, IdentityFile, Recipient,
};
use anyhow::{bail, Context, Result};

/// Environment variable name for providing passphrase to decrypt identity files
const AGE_PASSPHRASE_ENV: &str = "AGE_PASSPHRASE";

/// Callbacks for identity file decryption.
/// If AGE_PASSPHRASE environment variable is set, it will be used for decrypting
/// passphrase-protected identity files in automated/non-interactive mode.
#[derive(Clone)]
struct IdentityCallbacks;

impl Callbacks for IdentityCallbacks {
    fn display_message(&self, _message: &str) {}
    
    fn confirm(&self, _message: &str, _yes_string: &str, _no_string: Option<&str>) -> Option<bool> {
        None
    }
    
    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }
    
    fn request_passphrase(&self, _description: &str) -> Option<age::secrecy::SecretString> {
        env::var(AGE_PASSPHRASE_ENV).ok().map(|p| p.into())
    }
}

/// Callbacks that do nothing - used for plugin recipients where no passphrase is needed
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
            log::error!("Decryption error: {:?}", e);
            bail!(e)
        }
    };

    let identity_paths: Vec<_> = identities.iter().map(|p| p.as_ref().display().to_string()).collect();
    let mut reader = decryptor.decrypt(id_refs.into_iter())
        .with_context(|| format!(
            "Failed to decrypt: no matching identity found. Configured identities: [{}]",
            identity_paths.join(", ")
        ))?;
    reader.read_to_end(&mut decrypted)?;
    Ok(Some(decrypted))
}

fn load_identities(identities: &[impl AsRef<Path>]) -> Result<Vec<Box<dyn Identity + Send>>> {
    let mut all_identities: Vec<Box<dyn Identity + Send>> = vec![];
    
    for path in identities {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        // Try parsing as plaintext identity file first
        match IdentityFile::from_file(path_str.clone()) {
            Ok(identity_file) => {
                let file_identities = identity_file
                    .with_callbacks(IdentityCallbacks)
                    .into_identities()
                    .with_context(|| format!("Failed to parse identities from: {:?}", path))?;
                // Convert from Box<dyn Identity + Send + Sync> to Box<dyn Identity + Send>
                all_identities.extend(file_identities.into_iter().map(|i| i as Box<dyn Identity + Send>));
            }
            Err(_) => {
                // Try as encrypted identity file - decrypt it first, then parse as plaintext
                let file = File::open(path)
                    .with_context(|| format!("Failed to open identity file: {:?}", path))?;
                let reader = ArmoredReader::new(BufReader::new(file));
                
                // Check if it's a passphrase-encrypted file and decrypt it
                let decryptor = match Decryptor::new(reader) {
                    Ok(d) if d.is_scrypt() => d,
                    Ok(_) => bail!("Encrypted identity file {:?} is not passphrase-encrypted", path),
                    Err(e) => bail!("Failed to parse encrypted identity file {:?}: {}", path, e),
                };
                
                // Get passphrase from environment
                let passphrase = env::var(AGE_PASSPHRASE_ENV)
                    .with_context(|| format!("AGE_PASSPHRASE environment variable not set, needed to decrypt {:?}", path))?;
                
                // Decrypt the identity file
                let decrypted = {
                    let mut reader = decryptor.decrypt(std::iter::once(
                        &age::scrypt::Identity::new(passphrase.into()) as &dyn Identity
                    ))?;
                    let mut buf = Vec::new();
                    reader.read_to_end(&mut buf)?;
                    buf
                };
                
                // Parse the decrypted content as a plaintext identity file
                let decrypted_str = String::from_utf8(decrypted)
                    .with_context(|| format!("Decrypted identity file {:?} is not valid UTF-8", path))?;
                
                let identity_file = IdentityFile::from_buffer(decrypted_str.as_bytes())
                    .with_context(|| format!("Failed to parse decrypted identity file {:?}", path))?;
                
                let file_identities = identity_file
                    .with_callbacks(IdentityCallbacks)
                    .into_identities()
                    .with_context(|| format!("Failed to load identities from decrypted {:?}", path))?;
                
                all_identities.extend(file_identities.into_iter().map(|i| i as Box<dyn Identity + Send>));
            }
        }
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

/// Validates an identity file.
/// Returns Ok(None) for valid plaintext identities or decrypted encrypted identities.
/// Returns Ok(Some(note)) with a note for encrypted identities when AGE_PASSPHRASE is not set.
pub(crate) fn validate_identity(identity: impl AsRef<Path>) -> Result<Option<String>> {
    let path = identity.as_ref();
    let path_str = path.to_string_lossy().to_string();
    
    // Try parsing as plaintext identity file first
    match IdentityFile::from_file(path_str.clone()) {
        Ok(identity_file) => {
            identity_file
                .with_callbacks(IdentityCallbacks)
                .into_identities()
                .with_context(|| format!("Failed to parse identity from: {:?}", path))?;
            Ok(None)
        }
        Err(_) => {
            // Try as encrypted identity file
            let file = File::open(path)
                .with_context(|| format!("Failed to open identity file: {:?}", path))?;
            let reader = ArmoredReader::new(BufReader::new(file));
            
            // Check if it's a valid encrypted file
            let decryptor = match Decryptor::new(reader) {
                Ok(d) if d.is_scrypt() => d,
                Ok(_) => bail!("Encrypted identity file {:?} is not passphrase-encrypted", path),
                Err(e) => bail!("File {:?} is neither a valid plaintext nor encrypted identity file: {}", path, e),
            };
            
            // If AGE_PASSPHRASE is set, try to decrypt and validate
            // Otherwise, just accept that it's a valid encrypted format
            match env::var(AGE_PASSPHRASE_ENV) {
                Ok(passphrase) => {
                    // Decrypt and validate the identity file
                    let decrypted = {
                        let mut reader = decryptor.decrypt(std::iter::once(
                            &age::scrypt::Identity::new(passphrase.into()) as &dyn Identity
                        )).with_context(|| format!("Failed to decrypt {:?} with AGE_PASSPHRASE", path))?;
                        let mut buf = Vec::new();
                        reader.read_to_end(&mut buf)?;
                        buf
                    };
                    
                    let decrypted_str = String::from_utf8(decrypted)
                        .with_context(|| format!("Decrypted identity file {:?} is not valid UTF-8", path))?;
                    
                    let identity_file = IdentityFile::from_buffer(decrypted_str.as_bytes())
                        .with_context(|| format!("Failed to parse decrypted identity file {:?}", path))?;
                    
                    identity_file
                        .with_callbacks(IdentityCallbacks)
                        .into_identities()
                        .with_context(|| format!("Failed to load identities from decrypted {:?}", path))?;
                    
                    Ok(None)
                }
                Err(_) => {
                    // No passphrase set - just validate format, don't require decryption
                    Ok(Some("encrypted, AGE_PASSPHRASE not detected, decryption was not tested".to_string()))
                }
            }
        }
    }
}
