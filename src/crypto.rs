use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const ENVELOPE_MAGIC: &[u8; 8] = b"BLINDG01";

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyFile {
    pub repository_id: String,
    encryption_key: String,
    signing_key: String,
}

impl KeyFile {
    pub fn generate() -> Self {
        let mut repository_id = [0_u8; 16];
        let mut encryption_key = [0_u8; 32];
        OsRng.fill_bytes(&mut repository_id);
        OsRng.fill_bytes(&mut encryption_key);
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            repository_id: hex::encode(repository_id),
            encryption_key: BASE64.encode(encryption_key),
            signing_key: BASE64.encode(signing_key.to_bytes()),
        }
    }

    pub fn write_new(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("create key file {}", path.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read key file {}", path.display()))?;
        let key: Self = serde_json::from_slice(&bytes).context("parse key file")?;
        key.encryption_key_bytes()?;
        key.signing_key()?;
        Ok(key)
    }

    pub fn writer_id(&self) -> Result<String> {
        Ok(hex::encode(self.signing_key()?.verifying_key().to_bytes()))
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signing_key()?.sign(message).to_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8], writer_id: &str) -> Result<()> {
        if writer_id != self.writer_id()? {
            bail!("manifest was signed by an unauthorized writer")
        }
        let signature = Signature::from_slice(signature).context("invalid Ed25519 signature")?;
        let public_bytes: [u8; 32] = hex::decode(writer_id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid writer id length"))?;
        let public = VerifyingKey::from_bytes(&public_bytes)?;
        public
            .verify(message, &signature)
            .context("manifest signature verification failed")
    }

    pub fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new((&self.encryption_key_bytes()?).into());
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut envelope =
            Vec::with_capacity(ENVELOPE_MAGIC.len() + nonce.len() + ciphertext.len());
        envelope.extend_from_slice(ENVELOPE_MAGIC);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub fn open(&self, envelope: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if envelope.len() < ENVELOPE_MAGIC.len() + 24 + 16
            || &envelope[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC
        {
            bail!("invalid encrypted object envelope")
        }
        let nonce_start = ENVELOPE_MAGIC.len();
        let nonce_end = nonce_start + 24;
        let cipher = XChaCha20Poly1305::new((&self.encryption_key_bytes()?).into());
        cipher
            .decrypt(
                XNonce::from_slice(&envelope[nonce_start..nonce_end]),
                Payload {
                    msg: &envelope[nonce_end..],
                    aad: associated_data,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypted object authentication failed"))
    }

    fn encryption_key_bytes(&self) -> Result<[u8; 32]> {
        BASE64
            .decode(&self.encryption_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid encryption key length"))
    }

    fn signing_key(&self) -> Result<SigningKey> {
        let bytes: [u8; 32] = BASE64
            .decode(&self.signing_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signing key length"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

pub fn object_id(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_is_randomized_and_authenticated() {
        let key = KeyFile::generate();
        let first = key.seal(b"same", b"pack").unwrap();
        let second = key.seal(b"same", b"pack").unwrap();
        assert_ne!(first, second);
        assert_eq!(key.open(&first, b"pack").unwrap(), b"same");

        let mut tampered = first;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(key.open(&tampered, b"pack").is_err());
        assert!(key.open(&second, b"manifest").is_err());
    }
}
