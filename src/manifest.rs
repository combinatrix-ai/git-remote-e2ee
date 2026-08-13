use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{KeyFile, open_with_key, random_key, seal_with_key, verify_domain};
use crate::policy::PolicyState;

pub const FORMAT_VERSION: u32 = 2;
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"git-remote-e2ee manifest v2\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackDescriptor {
    pub id: String,
    pub plaintext_size: u64,
    pub wrapped_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub format_version: u32,
    pub repository_root: String,
    pub generation: u64,
    pub previous: Option<String>,
    pub policy_id: String,
    pub policy_generation: u64,
    pub epoch: u64,
    pub authorization: ManifestAuthorization,
    pub refs: BTreeMap<String, String>,
    pub packs: Vec<PackDescriptor>,
}

impl Manifest {
    pub fn genesis(repository_root: String, policy: &PolicyState) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            repository_root,
            generation: 0,
            previous: None,
            policy_id: policy.id.clone(),
            policy_generation: policy.body.generation,
            epoch: policy.body.epoch,
            authorization: ManifestAuthorization::PolicyTransition,
            refs: BTreeMap::new(),
            packs: Vec::new(),
        }
    }

    pub fn validate_successor(&self, previous_id: &str, previous: &Manifest) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            bail!("unsupported manifest format {}", self.format_version)
        }
        if self.repository_root != previous.repository_root {
            bail!("manifest repository root changed")
        }
        if self.generation != previous.generation + 1 {
            bail!("manifest generation is not consecutive")
        }
        if self.previous.as_deref() != Some(previous_id) {
            bail!("manifest previous pointer does not match")
        }
        if self.policy_generation < previous.policy_generation {
            bail!("manifest policy generation moved backwards")
        }
        match self.authorization {
            ManifestAuthorization::Writer => {
                if self.policy_id != previous.policy_id
                    || self.policy_generation != previous.policy_generation
                    || self.epoch != previous.epoch
                {
                    bail!("writer manifest changed policy state")
                }
            }
            ManifestAuthorization::PolicyTransition => {
                if self.policy_generation != previous.policy_generation + 1 {
                    bail!("policy transition did not advance policy generation by one")
                }
            }
        }
        if self.packs.len() < previous.packs.len() {
            bail!("manifest removed packs from the inventory")
        }
        for (current, old) in self.packs.iter().zip(&previous.packs) {
            if current.id != old.id || current.plaintext_size != old.plaintext_size {
                bail!("manifest rewrote the pack inventory")
            }
            if self.epoch == previous.epoch && current.wrapped_key != old.wrapped_key {
                bail!("manifest rewrote a pack key without rotating the epoch")
            }
            if self.epoch != previous.epoch && current.wrapped_key == old.wrapped_key {
                bail!("manifest did not rewrap every pack key after epoch rotation")
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestAuthorization {
    Writer,
    PolicyTransition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestHeader {
    pub format_version: u32,
    pub repository_root: String,
    pub generation: u64,
    pub previous: Option<String>,
    pub policy_id: String,
    pub policy_generation: u64,
    pub epoch: u64,
    pub manifest_key_wrap: String,
    pub signer_device_id: String,
    pub authorization: ManifestAuthorization,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    refs: BTreeMap<String, String>,
    packs: Vec<PackDescriptor>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEnvelope {
    header: String,
    body_ciphertext: String,
    signature: String,
}

struct ParsedEnvelope {
    header: ManifestHeader,
    exact_header: Vec<u8>,
    body_ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

pub fn seal_manifest(
    key: &KeyFile,
    policy: &PolicyState,
    epoch_key: &[u8; 32],
    authorization: ManifestAuthorization,
    manifest: Manifest,
) -> Result<Vec<u8>> {
    validate_manifest_policy(&manifest, policy)?;
    let manifest_key = random_key();
    let key_wrap = seal_with_key(
        epoch_key,
        &manifest_key,
        &manifest_key_aad(
            &manifest.repository_root,
            manifest.generation,
            manifest.epoch,
        ),
    )?;
    let header = ManifestHeader {
        format_version: manifest.format_version,
        repository_root: manifest.repository_root.clone(),
        generation: manifest.generation,
        previous: manifest.previous.clone(),
        policy_id: manifest.policy_id.clone(),
        policy_generation: manifest.policy_generation,
        epoch: manifest.epoch,
        manifest_key_wrap: BASE64.encode(key_wrap),
        signer_device_id: key.device_id()?,
        authorization,
    };
    let exact_header = serde_json::to_vec(&header)?;
    let body = serde_json::to_vec(&ManifestBody {
        refs: manifest.refs,
        packs: manifest.packs,
    })?;
    let body_ciphertext = seal_with_key(
        &manifest_key,
        &body,
        &manifest_body_aad(&header.repository_root, header.generation),
    )?;
    let signed = manifest_signed_bytes(&exact_header, &body_ciphertext);
    let envelope = ManifestEnvelope {
        header: BASE64.encode(exact_header),
        body_ciphertext: BASE64.encode(body_ciphertext),
        signature: BASE64.encode(key.sign_domain(MANIFEST_SIGNATURE_DOMAIN, &signed)?),
    };
    Ok(serde_json::to_vec(&envelope)?)
}

pub fn read_manifest_header(
    encrypted: &[u8],
    policy: &PolicyState,
    parent_policy: Option<&PolicyState>,
) -> Result<ManifestHeader> {
    let parsed = parse_envelope(encrypted)?;
    let header = parsed.header;
    if header.format_version != FORMAT_VERSION {
        bail!("unsupported manifest format {}", header.format_version)
    }
    if header.repository_root != policy.body.repository_root
        || header.policy_id != policy.id
        || header.policy_generation != policy.body.generation
        || header.epoch != policy.body.epoch
    {
        bail!("manifest header does not match its policy")
    }
    let signer = match header.authorization {
        ManifestAuthorization::Writer => policy
            .device(&header.signer_device_id)
            .filter(|device| device.active() && device.roles.writer)
            .context("manifest was not signed by an active writer")?,
        ManifestAuthorization::PolicyTransition => {
            let authorizing = parent_policy.unwrap_or(policy);
            authorizing
                .device(&header.signer_device_id)
                .filter(|device| device.active() && device.roles.administrator)
                .context("policy transition manifest was not signed by a parent administrator")?
        }
    };
    verify_domain(
        &signer.public.signing_public_key,
        MANIFEST_SIGNATURE_DOMAIN,
        &manifest_signed_bytes(&parsed.exact_header, &parsed.body_ciphertext),
        &parsed.signature,
    )?;
    Ok(header)
}

pub fn peek_manifest_header(encrypted: &[u8]) -> Result<ManifestHeader> {
    Ok(parse_envelope(encrypted)?.header)
}

pub fn open_manifest(
    encrypted: &[u8],
    policy: &PolicyState,
    parent_policy: Option<&PolicyState>,
    epoch_key: &[u8; 32],
) -> Result<Manifest> {
    let header = read_manifest_header(encrypted, policy, parent_policy)?;
    let envelope: ManifestEnvelope = serde_json::from_slice(encrypted)?;
    let manifest_key: [u8; 32] = open_with_key(
        epoch_key,
        &BASE64.decode(&header.manifest_key_wrap)?,
        &manifest_key_aad(&header.repository_root, header.generation, header.epoch),
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid manifest key length"))?;
    let body_ciphertext = BASE64.decode(envelope.body_ciphertext)?;
    let body_bytes = open_with_key(
        &manifest_key,
        &body_ciphertext,
        &manifest_body_aad(&header.repository_root, header.generation),
    )?;
    let body: ManifestBody = serde_json::from_slice(&body_bytes).context("parse manifest body")?;
    Ok(Manifest {
        format_version: header.format_version,
        repository_root: header.repository_root,
        generation: header.generation,
        previous: header.previous,
        policy_id: header.policy_id,
        policy_generation: header.policy_generation,
        epoch: header.epoch,
        authorization: header.authorization,
        refs: body.refs,
        packs: body.packs,
    })
}

pub fn wrap_pack_key(
    epoch_key: &[u8; 32],
    repository_root: &str,
    epoch: u64,
    pack_id: &str,
    pack_key: &[u8; 32],
) -> Result<String> {
    Ok(BASE64.encode(seal_with_key(
        epoch_key,
        pack_key,
        &pack_key_aad(repository_root, epoch, pack_id),
    )?))
}

pub fn unwrap_pack_key(
    epoch_key: &[u8; 32],
    repository_root: &str,
    epoch: u64,
    descriptor: &PackDescriptor,
) -> Result<[u8; 32]> {
    open_with_key(
        epoch_key,
        &BASE64.decode(&descriptor.wrapped_key)?,
        &pack_key_aad(repository_root, epoch, &descriptor.id),
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid pack key length"))
}

pub fn pack_aad(repository_root: &str) -> Vec<u8> {
    format!("git-remote-e2ee pack v2\0{repository_root}").into_bytes()
}

fn parse_envelope(encrypted: &[u8]) -> Result<ParsedEnvelope> {
    let envelope: ManifestEnvelope =
        serde_json::from_slice(encrypted).context("parse manifest envelope")?;
    let exact_header = BASE64
        .decode(envelope.header)
        .context("decode manifest header")?;
    let header: ManifestHeader =
        serde_json::from_slice(&exact_header).context("parse manifest header")?;
    Ok(ParsedEnvelope {
        header,
        exact_header,
        body_ciphertext: BASE64.decode(envelope.body_ciphertext)?,
        signature: BASE64.decode(envelope.signature)?,
    })
}

fn validate_manifest_policy(manifest: &Manifest, policy: &PolicyState) -> Result<()> {
    if manifest.format_version != FORMAT_VERSION
        || manifest.repository_root != policy.body.repository_root
        || manifest.policy_id != policy.id
        || manifest.policy_generation != policy.body.generation
        || manifest.epoch != policy.body.epoch
    {
        bail!("manifest does not match policy state")
    }
    Ok(())
}

fn manifest_signed_bytes(exact_header: &[u8], body_ciphertext: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(exact_header.len() + 32);
    bytes.extend_from_slice(exact_header);
    bytes.extend_from_slice(&Sha256::digest(body_ciphertext));
    bytes
}

fn manifest_key_aad(root: &str, generation: u64, epoch: u64) -> Vec<u8> {
    format!("git-remote-e2ee manifest key v2\0{root}\0{generation}\0{epoch}").into_bytes()
}

fn manifest_body_aad(root: &str, generation: u64) -> Vec<u8> {
    format!("git-remote-e2ee manifest body v2\0{root}\0{generation}").into_bytes()
}

fn pack_key_aad(root: &str, epoch: u64, pack_id: &str) -> Vec<u8> {
    format!("git-remote-e2ee pack key v2\0{root}\0{epoch}\0{pack_id}").into_bytes()
}
