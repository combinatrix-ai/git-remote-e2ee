use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use rand::RngCore;
use rand::rngs::OsRng;
use rand_09::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SYMMETRIC_MAGIC: &[u8; 8] = b"E2EES03\0";
const HPKE_INFO: &[u8] = b"git-remote-e2ee generation key v3";
const KEY_COMMITMENT_DOMAIN: &[u8] = b"git-remote-e2ee generation key commitment v3\0";
const SUBKEY_SALT: &[u8] = b"git-remote-e2ee subkey derivation v3\0";

type HpkeKem = X25519HkdfSha256;
type HpkeKdf = HkdfSha256;
type HpkeAead = ChaCha20Poly1305;

pub type SecretKey = Zeroizing<[u8; 32]>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SubkeyKind {
    ManifestBody = 1,
    Pack = 2,
    PredecessorLink = 3,
}

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
            format_version: 3,
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
            format_version: 3,
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
        if key.format_version != 3 {
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
        let mut identity = Vec::with_capacity(96);
        identity.extend_from_slice(b"git-remote-e2ee device id v3\0");
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

    pub fn unwrap_generation_key(
        &self,
        encapsulated_key: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<SecretKey> {
        let encapsulated = <HpkeKem as Kem>::EncappedKey::from_bytes(encapsulated_key)
            .map_err(|_| anyhow::anyhow!("invalid HPKE encapsulated key"))?;
        let private = self.wrapping_private_key()?;
        let plaintext = Zeroizing::new(
            hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
                &OpModeR::Base,
                &private,
                &encapsulated,
                HPKE_INFO,
                ciphertext,
                aad,
            )
            .map_err(|_| anyhow::anyhow!("device is not able to unwrap the generation key"))?,
        );
        let key = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid generation key length"))?;
        Ok(Zeroizing::new(key))
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

pub fn wrap_generation_key(
    public_key: &str,
    generation_key: &[u8; 32],
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
        generation_key,
        aad,
        &mut rng,
    )
    .map_err(|_| anyhow::anyhow!("HPKE generation-key wrapping failed"))?;
    Ok((encapsulated.to_bytes().to_vec(), ciphertext))
}

pub fn random_key() -> SecretKey {
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    Zeroizing::new(key)
}

pub fn commit_key(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(KEY_COMMITMENT_DOMAIN);
    hasher.update(key);
    hex::encode(hasher.finalize())
}

pub fn verify_key_commitment(key: &[u8; 32], commitment: &str) -> Result<()> {
    let expected = hex::decode(commitment).context("decode generation key commitment")?;
    let actual = hex::decode(commit_key(key)).expect("hex digest");
    if expected.len() != actual.len() || !bool::from(expected.ct_eq(&actual)) {
        bail!("generation key does not match the signed commitment")
    }
    Ok(())
}

pub fn derive_subkey(
    generation_key: &[u8; 32],
    repository_root: &str,
    generation: u64,
    kind: SubkeyKind,
    ordinal: u64,
) -> Result<SecretKey> {
    let root = hex::decode(repository_root).context("decode repository root for HKDF")?;
    if root.len() != 32 {
        bail!("invalid repository root length for HKDF")
    }
    let hkdf = Hkdf::<Sha256>::new(Some(SUBKEY_SALT), generation_key);
    let mut info = Vec::with_capacity(32 + 8 + 1 + 8);
    info.extend_from_slice(&root);
    info.extend_from_slice(&generation.to_le_bytes());
    info.push(kind as u8);
    info.extend_from_slice(&ordinal.to_le_bytes());
    let mut output = [0_u8; 32];
    hkdf.expand(&info, &mut output)
        .map_err(|_| anyhow::anyhow!("HKDF subkey derivation failed"))?;
    Ok(Zeroizing::new(output))
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
    let mut identity = Vec::with_capacity(96);
    identity.extend_from_slice(b"git-remote-e2ee device id v3\0");
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
    fn hpke_generation_wrap_is_recipient_specific() {
        let first = KeyFile::generate();
        let second = KeyFile::generate_for_repository(first.repository_root.clone()).unwrap();
        let generation_key = random_key();
        let public = first.public_device().unwrap();
        let (enc, ciphertext) =
            wrap_generation_key(&public.wrapping_public_key, &generation_key, b"manifest").unwrap();
        assert_eq!(
            first
                .unwrap_generation_key(&enc, &ciphertext, b"manifest")
                .unwrap(),
            generation_key
        );
        assert!(
            second
                .unwrap_generation_key(&enc, &ciphertext, b"manifest")
                .is_err()
        );
    }

    #[test]
    fn derived_subkeys_are_context_separated_and_committed() {
        let key = random_key();
        let root = KeyFile::generate().repository_root.clone();
        let body = derive_subkey(&key, &root, 4, SubkeyKind::ManifestBody, 0).unwrap();
        let pack = derive_subkey(&key, &root, 4, SubkeyKind::Pack, 0).unwrap();
        let next_pack = derive_subkey(&key, &root, 4, SubkeyKind::Pack, 1).unwrap();
        assert_ne!(*body, *pack);
        assert_ne!(*pack, *next_pack);
        let commitment = commit_key(&key);
        verify_key_commitment(&key, &commitment).unwrap();
        let wrong = random_key();
        assert!(verify_key_commitment(&wrong, &commitment).is_err());
    }
}
