use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use rand::RngCore;
use rand::rngs::OsRng;
use rand_09::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SYMMETRIC_MAGIC: &[u8; 8] = b"E2EES02\0";
const HPKE_INFO: &[u8] = b"git-remote-e2ee epoch key v2";

type HpkeKem = X25519HkdfSha256;
type HpkeKdf = HkdfSha256;
type HpkeAead = ChaCha20Poly1305;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDevice {
    pub repository_root: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_public_key: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    pub format_version: u32,
    pub repository_root: String,
    signing_private_key: String,
    wrapping_private_key: String,
}

impl KeyFile {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut rng = StdRng::from_os_rng();
        let (wrapping_private, wrapping_public) = HpkeKem::gen_keypair(&mut rng);
        let repository_root = repository_root_for_public_keys(
            &signing_key.verifying_key().to_bytes(),
            wrapping_public.to_bytes().as_slice(),
        );
        Self {
            format_version: 2,
            repository_root,
            signing_private_key: BASE64.encode(signing_key.to_bytes()),
            wrapping_private_key: BASE64.encode(wrapping_private.to_bytes()),
        }
    }

    pub fn generate_for_repository(repository_root: String) -> Result<Self> {
        validate_root(&repository_root)?;
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut rng = StdRng::from_os_rng();
        let (wrapping_private, _) = HpkeKem::gen_keypair(&mut rng);
        Ok(Self {
            format_version: 2,
            repository_root,
            signing_private_key: BASE64.encode(signing_key.to_bytes()),
            wrapping_private_key: BASE64.encode(wrapping_private.to_bytes()),
        })
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
        if key.format_version != 2 {
            bail!("unsupported key file format {}", key.format_version)
        }
        validate_root(&key.repository_root)?;
        key.signing_key()?;
        key.wrapping_private_key()?;
        Ok(key)
    }

    pub fn public_device(&self) -> Result<PublicDevice> {
        let signing_public = self.signing_key()?.verifying_key().to_bytes();
        let wrapping_private = self.wrapping_private_key()?;
        let wrapping_public = HpkeKem::sk_to_pk(&wrapping_private).to_bytes();
        let mut identity = Vec::with_capacity(64);
        identity.extend_from_slice(&signing_public);
        identity.extend_from_slice(&wrapping_public);
        Ok(PublicDevice {
            repository_root: self.repository_root.clone(),
            device_id: hex::encode(Sha256::digest(&identity)),
            signing_public_key: BASE64.encode(signing_public),
            wrapping_public_key: BASE64.encode(wrapping_public),
        })
    }

    pub fn device_id(&self) -> Result<String> {
        Ok(self.public_device()?.device_id)
    }

    pub fn sign_domain(&self, domain: &[u8], exact_bytes: &[u8]) -> Result<Vec<u8>> {
        let digest = Sha256::digest(exact_bytes);
        let mut message = Vec::with_capacity(domain.len() + digest.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(&digest);
        Ok(self.signing_key()?.sign(&message).to_bytes().to_vec())
    }

    pub fn unwrap_epoch_key(
        &self,
        encapsulated_key: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<[u8; 32]> {
        let encapsulated = <HpkeKem as Kem>::EncappedKey::from_bytes(encapsulated_key)
            .map_err(|_| anyhow::anyhow!("invalid HPKE encapsulated key"))?;
        let private = self.wrapping_private_key()?;
        let plaintext = hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &private,
            &encapsulated,
            HPKE_INFO,
            ciphertext,
            aad,
        )
        .map_err(|_| anyhow::anyhow!("device is not able to unwrap the repository epoch key"))?;
        plaintext
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid epoch key length"))
    }

    fn signing_key(&self) -> Result<SigningKey> {
        let bytes: [u8; 32] = BASE64
            .decode(&self.signing_private_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signing key length"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    fn wrapping_private_key(&self) -> Result<<HpkeKem as Kem>::PrivateKey> {
        let bytes = BASE64.decode(&self.wrapping_private_key)?;
        <HpkeKem as Kem>::PrivateKey::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid HPKE private key"))
    }
}

impl PublicDevice {
    pub fn write_new(&self, path: &Path) -> Result<()> {
        validate_public_device(self)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(path)
            .with_context(|| format!("create public device file {}", path.display()))?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("read public device file {}", path.display()))?;
        let public: Self = serde_json::from_slice(&bytes).context("parse public device file")?;
        validate_public_device(&public)?;
        Ok(public)
    }
}

pub fn verify_domain(
    public_key: &str,
    domain: &[u8],
    exact_bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    let public_bytes: [u8; 32] = BASE64
        .decode(public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 public key length"))?;
    let public = VerifyingKey::from_bytes(&public_bytes)?;
    let signature = Signature::from_slice(signature).context("invalid Ed25519 signature")?;
    let digest = Sha256::digest(exact_bytes);
    let mut message = Vec::with_capacity(domain.len() + digest.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&digest);
    public
        .verify_strict(&message, &signature)
        .context("signature verification failed")
}

pub fn wrap_epoch_key(
    public_key: &str,
    epoch_key: &[u8; 32],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let public_bytes = BASE64.decode(public_key)?;
    let public = <HpkeKem as Kem>::PublicKey::from_bytes(&public_bytes)
        .map_err(|_| anyhow::anyhow!("invalid HPKE public key"))?;
    let mut rng = StdRng::from_os_rng();
    let (encapsulated, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem, _>(
        &OpModeS::Base,
        &public,
        HPKE_INFO,
        epoch_key,
        aad,
        &mut rng,
    )
    .map_err(|_| anyhow::anyhow!("HPKE epoch-key wrapping failed"))?;
    Ok((encapsulated.to_bytes().to_vec(), ciphertext))
}

pub fn random_key() -> [u8; 32] {
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn seal_with_key(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
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
    let mut envelope = Vec::with_capacity(SYMMETRIC_MAGIC.len() + nonce.len() + ciphertext.len());
    envelope.extend_from_slice(SYMMETRIC_MAGIC);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn open_with_key(key: &[u8; 32], envelope: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < SYMMETRIC_MAGIC.len() + 24 + 16
        || &envelope[..SYMMETRIC_MAGIC.len()] != SYMMETRIC_MAGIC
    {
        bail!("invalid encrypted object envelope")
    }
    let nonce_start = SYMMETRIC_MAGIC.len();
    let nonce_end = nonce_start + 24;
    let cipher = XChaCha20Poly1305::new(key.into());
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

pub fn object_id(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    BASE64
        .decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))
}

pub fn validate_public_device(device: &PublicDevice) -> Result<()> {
    validate_root(&device.repository_root)?;
    let signing = decode_public_key(&device.signing_public_key)?;
    let wrapping = decode_public_key(&device.wrapping_public_key)?;
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(&signing);
    identity.extend_from_slice(&wrapping);
    if device.device_id != hex::encode(Sha256::digest(&identity)) {
        bail!("device id does not match its public keys")
    }
    Ok(())
}

pub fn repository_root_for_device(device: &PublicDevice) -> Result<String> {
    Ok(repository_root_for_public_keys(
        &decode_public_key(&device.signing_public_key)?,
        &decode_public_key(&device.wrapping_public_key)?,
    ))
}

fn repository_root_for_public_keys(signing: &[u8], wrapping: &[u8]) -> String {
    let mut identity = Vec::with_capacity(32 + signing.len() + wrapping.len());
    identity.extend_from_slice(b"git-remote-e2ee repository root v2\0");
    identity.extend_from_slice(signing);
    identity.extend_from_slice(wrapping);
    hex::encode(Sha256::digest(identity))
}

fn validate_root(root: &str) -> Result<()> {
    if root.len() != 64 || !root.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("repository root must be a 32-byte lowercase hexadecimal value")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_ciphertext_is_randomized_and_context_bound() {
        let key = random_key();
        let first = seal_with_key(&key, b"same", b"pack").unwrap();
        let second = seal_with_key(&key, b"same", b"pack").unwrap();
        assert_ne!(first, second);
        assert_eq!(open_with_key(&key, &first, b"pack").unwrap(), b"same");
        assert!(open_with_key(&key, &second, b"manifest").is_err());
    }

    #[test]
    fn hpke_epoch_wrap_is_recipient_specific() {
        let first = KeyFile::generate();
        let second = KeyFile::generate_for_repository(first.repository_root.clone()).unwrap();
        let epoch = random_key();
        let public = first.public_device().unwrap();
        let (enc, ciphertext) =
            wrap_epoch_key(&public.wrapping_public_key, &epoch, b"policy").unwrap();
        assert_eq!(
            first
                .unwrap_epoch_key(&enc, &ciphertext, b"policy")
                .unwrap(),
            epoch
        );
        assert!(
            second
                .unwrap_epoch_key(&enc, &ciphertext, b"policy")
                .is_err()
        );
    }
}
