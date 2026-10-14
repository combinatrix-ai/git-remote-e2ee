use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32, Nonce, StreamBE32};
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

const SYMMETRIC_MAGIC: &[u8; 8] = b"E2EES04\0";
const PACK_STREAM_MAGIC: &[u8; 8] = b"E2EEPK4\0";
const HPKE_INFO: &[u8] = b"git-remote-e2ee generation key v4";
const KEY_COMMITMENT_DOMAIN: &[u8] = b"git-remote-e2ee generation key commitment v4\0";
const SUBKEY_SALT: &[u8] = b"git-remote-e2ee subkey derivation v4\0";
pub const PACK_STREAM_CHUNK_SIZE: usize = 1024 * 1024;
const PACK_STREAM_NONCE_SIZE: usize = 19;
const PACK_STREAM_TAG_SIZE: usize = 16;
const PACK_STREAM_HEADER_SIZE: usize = PACK_STREAM_MAGIC.len() + 4 + PACK_STREAM_NONCE_SIZE;

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
        Ok(PublicDevice {
            repository_root: self.repository_root.clone(),
            device_id: device_id_for_public_keys(&signing_public, wrapping_public.as_slice()),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSealResult {
    pub object_id: String,
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
}

struct DigestWriter<W> {
    inner: W,
    hasher: Sha256,
    count: u64,
}

impl<W: Write> DigestWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }

    fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.count)
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(data)?;
        self.hasher.update(&data[..written]);
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn pack_stream_aad(base_aad: &[u8], header: &[u8]) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee pack stream v4\0".to_vec();
    aad.extend_from_slice(&(base_aad.len() as u32).to_le_bytes());
    aad.extend_from_slice(base_aad);
    aad.extend_from_slice(&(header.len() as u32).to_le_bytes());
    aad.extend_from_slice(header);
    aad
}

fn read_chunk(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut chunk = vec![0_u8; PACK_STREAM_CHUNK_SIZE];
    let mut filled = 0;
    while filled < chunk.len() {
        match reader.read(&mut chunk[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    chunk.truncate(filled);
    Ok(chunk)
}

pub fn seal_pack_stream(
    key: &[u8; 32],
    mut plaintext: impl Read,
    ciphertext: impl Write,
    base_aad: &[u8],
) -> Result<StreamSealResult> {
    let mut nonce = [0_u8; PACK_STREAM_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let mut header = Vec::with_capacity(PACK_STREAM_HEADER_SIZE);
    header.extend_from_slice(PACK_STREAM_MAGIC);
    header.extend_from_slice(&(PACK_STREAM_CHUNK_SIZE as u32).to_le_bytes());
    header.extend_from_slice(&nonce);
    let aad = pack_stream_aad(base_aad, &header);
    let stream_nonce =
        Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::from_slice(&nonce);
    let mut encryptor = EncryptorBE32::<XChaCha20Poly1305>::new(key.into(), stream_nonce);
    let mut output = DigestWriter::new(ciphertext);
    output.write_all(&header)?;

    let mut current = read_chunk(&mut plaintext)?;
    if current.is_empty() {
        bail!("cannot encrypt an empty pack stream")
    }
    let mut plaintext_size = 0_u64;
    let mut segments = 0_u64;
    loop {
        let next = read_chunk(&mut plaintext)?;
        plaintext_size = plaintext_size
            .checked_add(current.len() as u64)
            .context("pack plaintext size overflow")?;
        segments += 1;
        if segments >= u32::MAX as u64 {
            bail!("pack stream exceeds segment counter limit")
        }
        if next.is_empty() {
            encryptor
                .encrypt_last_in_place(&aad, &mut current)
                .map_err(|_| anyhow::anyhow!("pack stream encryption failed"))?;
            output.write_all(&current)?;
            break;
        }
        encryptor
            .encrypt_next_in_place(&aad, &mut current)
            .map_err(|_| anyhow::anyhow!("pack stream encryption failed"))?;
        output.write_all(&current)?;
        current = next;
    }
    output.flush()?;
    let (object_id, ciphertext_size) = output.finish();
    Ok(StreamSealResult {
        object_id,
        plaintext_size,
        ciphertext_size,
    })
}

pub fn open_pack_stream(
    key: &[u8; 32],
    mut ciphertext: impl Read,
    mut plaintext: impl Write,
    base_aad: &[u8],
    plaintext_size: u64,
    expected_id: &str,
) -> Result<u64> {
    if plaintext_size == 0 {
        bail!("pack plaintext size must be nonzero")
    }
    let mut header = [0_u8; PACK_STREAM_HEADER_SIZE];
    ciphertext
        .read_exact(&mut header)
        .context("truncated pack stream header")?;
    if &header[..PACK_STREAM_MAGIC.len()] != PACK_STREAM_MAGIC {
        bail!("invalid pack stream magic")
    }
    let chunk_size_start = PACK_STREAM_MAGIC.len();
    let chunk_size = u32::from_le_bytes(
        header[chunk_size_start..chunk_size_start + 4]
            .try_into()
            .expect("fixed chunk size field"),
    ) as usize;
    if chunk_size != PACK_STREAM_CHUNK_SIZE {
        bail!("unsupported pack stream chunk size")
    }
    let segments = plaintext_size.div_ceil(PACK_STREAM_CHUNK_SIZE as u64);
    if segments == 0 || segments >= u32::MAX as u64 {
        bail!("pack stream exceeds segment counter limit")
    }
    let tag_bytes = segments
        .checked_mul(PACK_STREAM_TAG_SIZE as u64)
        .context("pack stream tag size overflow")?;
    let expected_ciphertext_size = (PACK_STREAM_HEADER_SIZE as u64)
        .checked_add(plaintext_size)
        .and_then(|size| size.checked_add(tag_bytes))
        .context("pack ciphertext size overflow")?;

    let mut hasher = Sha256::new();
    hasher.update(header);
    let aad = pack_stream_aad(base_aad, &header);
    let nonce_start = chunk_size_start + 4;
    let stream_nonce = Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::from_slice(
        &header[nonce_start..],
    );
    let mut decryptor = Some(DecryptorBE32::<XChaCha20Poly1305>::new(
        key.into(),
        stream_nonce,
    ));
    let mut remaining = plaintext_size;
    let mut ciphertext_count = PACK_STREAM_HEADER_SIZE as u64;
    for segment in 0..segments {
        let plain_len = remaining.min(PACK_STREAM_CHUNK_SIZE as u64) as usize;
        let cipher_len = plain_len + PACK_STREAM_TAG_SIZE;
        let mut chunk = vec![0_u8; cipher_len];
        ciphertext
            .read_exact(&mut chunk)
            .with_context(|| format!("truncated pack stream segment {segment}"))?;
        hasher.update(&chunk);
        ciphertext_count += chunk.len() as u64;
        if segment + 1 == segments {
            decryptor
                .take()
                .expect("final pack segment is processed once")
                .decrypt_last_in_place(&aad, &mut chunk)
                .map_err(|_| anyhow::anyhow!("pack stream authentication failed"))?;
        } else {
            decryptor
                .as_mut()
                .expect("pack stream decryptor is active")
                .decrypt_next_in_place(&aad, &mut chunk)
                .map_err(|_| anyhow::anyhow!("pack stream authentication failed"))?;
        }
        if chunk.len() != plain_len {
            bail!("pack stream segment length mismatch")
        }
        plaintext.write_all(&chunk)?;
        remaining -= plain_len as u64;
    }
    let mut trailing = [0_u8; 1];
    loop {
        match ciphertext.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => bail!("pack stream has trailing data"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    if remaining != 0 || ciphertext_count != expected_ciphertext_size {
        bail!("pack stream size mismatch")
    }
    let actual_id = hex::encode(hasher.finalize());
    if actual_id != expected_id {
        bail!("pack ciphertext hash mismatch for {expected_id}")
    }
    plaintext.flush()?;
    Ok(ciphertext_count)
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
    if device.device_id != device_id_for_public_keys(&signing, &wrapping) {
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

fn device_id_for_public_keys(signing: &[u8], wrapping: &[u8]) -> String {
    let mut identity = Vec::with_capacity(32 + signing.len() + wrapping.len());
    identity.extend_from_slice(b"git-remote-e2ee device id v3\0");
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

    fn pack_bytes(size: usize) -> Vec<u8> {
        (0..size).map(|index| (index % 251) as u8).collect()
    }

    fn seal_test_pack(plaintext: &[u8]) -> (SecretKey, Vec<u8>, StreamSealResult) {
        let key = random_key();
        let mut ciphertext = Vec::new();
        let sealed = seal_pack_stream(&key, plaintext, &mut ciphertext, b"test-pack").unwrap();
        (key, ciphertext, sealed)
    }

    fn open_test_pack(
        key: &[u8; 32],
        ciphertext: &[u8],
        plaintext_size: u64,
        id: &str,
    ) -> Result<Vec<u8>> {
        let mut plaintext = Vec::new();
        open_pack_stream(
            key,
            ciphertext,
            &mut plaintext,
            b"test-pack",
            plaintext_size,
            id,
        )?;
        Ok(plaintext)
    }

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

    #[test]
    fn pack_stream_round_trips_chunk_boundaries() {
        for size in [
            1,
            PACK_STREAM_CHUNK_SIZE - 1,
            PACK_STREAM_CHUNK_SIZE,
            PACK_STREAM_CHUNK_SIZE + 1,
            PACK_STREAM_CHUNK_SIZE * 2,
        ] {
            let plaintext = pack_bytes(size);
            let (key, ciphertext, sealed) = seal_test_pack(&plaintext);
            assert_eq!(sealed.plaintext_size, size as u64);
            assert_eq!(sealed.ciphertext_size, ciphertext.len() as u64);
            assert_eq!(sealed.object_id, object_id(&ciphertext));
            assert_eq!(
                open_test_pack(&key, &ciphertext, size as u64, &sealed.object_id).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn pack_stream_is_randomized_and_context_bound() {
        let plaintext = pack_bytes(PACK_STREAM_CHUNK_SIZE + 1);
        let key = random_key();
        let mut first = Vec::new();
        let mut second = Vec::new();
        let first_result =
            seal_pack_stream(&key, plaintext.as_slice(), &mut first, b"context").unwrap();
        seal_pack_stream(&key, plaintext.as_slice(), &mut second, b"context").unwrap();
        assert_ne!(first, second);

        let mut output = Vec::new();
        assert!(
            open_pack_stream(
                &key,
                first.as_slice(),
                &mut output,
                b"other-context",
                plaintext.len() as u64,
                &first_result.object_id,
            )
            .is_err()
        );
        assert!(
            open_test_pack(
                &random_key(),
                &first,
                plaintext.len() as u64,
                &first_result.object_id,
            )
            .is_err()
        );

        let wrong_id = object_id(b"not this ciphertext");
        let mut authenticated_plaintext = Vec::new();
        let error = open_pack_stream(
            &key,
            first.as_slice(),
            &mut authenticated_plaintext,
            b"context",
            plaintext.len() as u64,
            &wrong_id,
        )
        .unwrap_err();
        assert!(error.to_string().contains("pack ciphertext hash mismatch"));
        assert_eq!(authenticated_plaintext, plaintext);
    }

    #[test]
    fn pack_stream_rejects_tamper_reorder_duplicate_truncation_and_trailing_data() {
        let plaintext = pack_bytes(PACK_STREAM_CHUNK_SIZE * 2 + 7);
        let (key, ciphertext, sealed) = seal_test_pack(&plaintext);
        let first_segment = PACK_STREAM_CHUNK_SIZE + PACK_STREAM_TAG_SIZE;

        let mut tampered = ciphertext.clone();
        tampered[PACK_STREAM_HEADER_SIZE + 17] ^= 1;
        assert!(open_test_pack(&key, &tampered, sealed.plaintext_size, &sealed.object_id).is_err());

        let mut reordered = ciphertext.clone();
        let segments = &mut reordered[PACK_STREAM_HEADER_SIZE..];
        let (first, rest) = segments.split_at_mut(first_segment);
        let second = &mut rest[..first_segment];
        first.swap_with_slice(second);
        assert!(
            open_test_pack(&key, &reordered, sealed.plaintext_size, &sealed.object_id).is_err()
        );

        let mut duplicated = ciphertext[..PACK_STREAM_HEADER_SIZE + first_segment].to_vec();
        duplicated.extend_from_slice(&ciphertext[PACK_STREAM_HEADER_SIZE..]);
        assert!(
            open_test_pack(&key, &duplicated, sealed.plaintext_size, &sealed.object_id).is_err()
        );

        let mut truncated = ciphertext.clone();
        truncated.pop();
        assert!(
            open_test_pack(&key, &truncated, sealed.plaintext_size, &sealed.object_id).is_err()
        );

        let mut trailing = ciphertext.clone();
        trailing.push(0);
        assert!(open_test_pack(&key, &trailing, sealed.plaintext_size, &sealed.object_id).is_err());
    }

    #[test]
    fn pack_stream_rejects_forged_header_size_and_legacy_magic() {
        let plaintext = pack_bytes(1234);
        let (key, ciphertext, sealed) = seal_test_pack(&plaintext);

        for wrong_size in [sealed.plaintext_size - 1, sealed.plaintext_size + 1] {
            assert!(open_test_pack(&key, &ciphertext, wrong_size, &sealed.object_id).is_err());
        }

        let mut forged_chunk_size = ciphertext.clone();
        forged_chunk_size[PACK_STREAM_MAGIC.len()..PACK_STREAM_MAGIC.len() + 4]
            .copy_from_slice(&4096_u32.to_le_bytes());
        assert!(
            open_test_pack(
                &key,
                &forged_chunk_size,
                sealed.plaintext_size,
                &sealed.object_id,
            )
            .is_err()
        );

        let mut legacy = ciphertext;
        legacy[..PACK_STREAM_MAGIC.len()].copy_from_slice(b"E2EEPK3\0");
        assert!(open_test_pack(&key, &legacy, sealed.plaintext_size, &sealed.object_id).is_err());
    }

    #[test]
    fn pack_stream_rejects_empty_plaintext() {
        let mut ciphertext = Vec::new();
        assert!(seal_pack_stream(&random_key(), &[][..], &mut ciphertext, b"test-pack").is_err());
    }
}
