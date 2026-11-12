//! The node's WireGuard key: made on the node the first time, kept in a file only root reads, never sent anywhere.
//! Its public half goes to the managers in the worker's report.

use std::path::Path;

use anyhow::{Context, Result};

pub struct Key {
    secret: x25519_dalek::StaticSecret,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

impl Key {
    /// The key in `path` (base64, as `wg genkey` writes it), made first when there is none. A file that is there but
    /// not a key is an error, not replaced: the managers route to the old one.
    pub fn load_or_make(path: &Path) -> Result<Self> {
        use base64::Engine;
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let bytes: [u8; 32] = b64().decode(text.trim()).ok().and_then(|b| b.try_into().ok()).with_context(|| format!("{} is not a WireGuard key", path.display()))?;
                Ok(Key { secret: x25519_dalek::StaticSecret::from(bytes) })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                write_private(path, format!("{}\n", b64().encode(secret.to_bytes())).as_bytes())?;
                tracing::info!("made this node's WireGuard key in {}", path.display());
                Ok(Key { secret })
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The public half, base64: what the other nodes know this one by.
    pub fn public(&self) -> String {
        use base64::Engine;
        b64().encode(x25519_dalek::PublicKey::from(&self.secret).as_bytes())
    }

    /// The private half, base64, for the interface; never logged or sent.
    pub fn private(&self) -> String {
        use base64::Engine;
        b64().encode(self.secret.to_bytes())
    }
}

/// Writes a file only its owner reads (0600 from the start, never readable in between).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path).and_then(|mut f| f.write_all(bytes)).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_made_once_kept_private_and_its_public_half_is_wireguard_s_form() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg.key");
        let k = Key::load_or_make(&path).unwrap();
        let public = k.public();
        assert_eq!(public.len(), 44, "base64 of 32 bytes: {public}");
        assert_eq!(Key::load_or_make(&path).unwrap().public(), public, "kept");
        assert_eq!(k.private().len(), 44);
        assert_ne!(k.private(), public);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(&path, "not a key").unwrap();
        assert!(Key::load_or_make(&path).is_err(), "a broken key is never replaced quietly: the managers know the old one");
    }
}
