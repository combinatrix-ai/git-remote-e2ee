use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{
    KeyFile, SecretKey, SubkeyKind, commit_key, derive_subkey, open_with_key, seal_with_key,
    verify_domain, verify_key_commitment, wrap_generation_key,
};
use crate::policy::PolicyState;

pub const FORMAT_VERSION: u32 = 3;
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"git-remote-e2ee manifest v3\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackDescriptor {
    pub id: String,
    pub plaintext_size: u64,
    pub generation: u64,
    pub ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationKeyEnvelope {
    pub device_id: String,
    pub encapsulated_key: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub format_version: u32,
    pub repository_root: String,
    pub generation: u64,
    pub previous: Option<String>,
    pub policy_id: String,
    pub policy_generation: u64,
    pub authorization: ManifestAuthorization,
    pub total_pack_count: u64,
    pub refs: BTreeMap<String, String>,
    pub new_packs: Vec<PackDescriptor>,
    pub predecessor_key_wrap: Option<String>,
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
            authorization: ManifestAuthorization::PolicyTransition,
            total_pack_count: 0,
            refs: BTreeMap::new(),
            new_packs: Vec::new(),
            predecessor_key_wrap: None,
        }
    }

    pub fn validate_genesis(&self, policy: &PolicyState) -> Result<()> {
        validate_manifest_policy(self, policy)?;
        if self.generation != 0
            || self.previous.is_some()
            || self.authorization != ManifestAuthorization::PolicyTransition
            || self.total_pack_count != 0
            || !self.refs.is_empty()
            || !self.new_packs.is_empty()
            || self.predecessor_key_wrap.is_some()
        {
            bail!("invalid genesis manifest")
        }
        Ok(())
    }

    pub fn validate_successor(
        &self,
        previous_id: &str,
        previous: &Manifest,
        selected_policy: &PolicyState,
    ) -> Result<()> {
        validate_manifest_policy(self, selected_policy)?;
        if self.repository_root != previous.repository_root {
            bail!("manifest repository root changed")
        }
        if self.generation != previous.generation + 1 {
            bail!("manifest generation is not consecutive")
        }
        if self.previous.as_deref() != Some(previous_id) {
            bail!("manifest previous pointer does not match")
        }
        if self.predecessor_key_wrap.is_none() {
            bail!("successor manifest is missing its predecessor key link")
        }
        validate_pack_delta(self)?;
        let expected_total = previous
            .total_pack_count
            .checked_add(self.new_packs.len() as u64)
            .context("manifest total pack count overflow")?;
        if self.total_pack_count != expected_total {
            bail!("manifest total pack count does not match its delta")
        }

        match self.authorization {
            ManifestAuthorization::Writer => {
                if self.policy_id != previous.policy_id
                    || self.policy_generation != previous.policy_generation
                {
                    bail!("writer manifest changed policy state")
                }
            }
            ManifestAuthorization::PolicyTransition => {
                if self.policy_generation != previous.policy_generation + 1
                    || selected_policy.body.previous.as_deref() != Some(previous.policy_id.as_str())
                {
                    bail!("policy transition did not select the direct policy child")
                }
                if self.refs != previous.refs || !self.new_packs.is_empty() {
                    bail!("policy transition changed Git content")
                }
            }
            ManifestAuthorization::Checkpoint => {
                bail!("checkpoint transitions are reserved but not implemented")
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
    Checkpoint,
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
    pub total_pack_count: u64,
    pub key_commitment: String,
    pub generation_key_envelopes: Vec<GenerationKeyEnvelope>,
    pub signer_device_id: String,
    pub authorization: ManifestAuthorization,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    refs: BTreeMap<String, String>,
    new_packs: Vec<PackDescriptor>,
    predecessor_key_wrap: Option<String>,
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
    generation_key: &[u8; 32],
    authorization: ManifestAuthorization,
    manifest: Manifest,
) -> Result<Vec<u8>> {
    validate_manifest_policy(&manifest, policy)?;
    let commitment = commit_key(generation_key);
    let mut envelopes = policy
        .body
        .devices
        .iter()
        .filter(|device| device.active() && device.roles.reader)
        .map(|device| {
            let aad = generation_key_aad(
                &manifest.repository_root,
                manifest.generation,
                &manifest.policy_id,
                &device.public.device_id,
                &commitment,
            );
            let (encapsulated, ciphertext) =
                wrap_generation_key(&device.public.wrapping_public_key, generation_key, &aad)?;
            Ok(GenerationKeyEnvelope {
                device_id: device.public.device_id.clone(),
                encapsulated_key: BASE64.encode(encapsulated),
                ciphertext: BASE64.encode(ciphertext),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    envelopes.sort_by(|a, b| a.device_id.cmp(&b.device_id));

    let header = ManifestHeader {
        format_version: manifest.format_version,
        repository_root: manifest.repository_root.clone(),
        generation: manifest.generation,
        previous: manifest.previous.clone(),
        policy_id: manifest.policy_id.clone(),
        policy_generation: manifest.policy_generation,
        total_pack_count: manifest.total_pack_count,
        key_commitment: commitment,
        generation_key_envelopes: envelopes,
        signer_device_id: key.device_id()?,
        authorization,
    };
    validate_recipient_set(&header, policy)?;
    let exact_header = serde_json::to_vec(&header)?;
    let body = serde_json::to_vec(&ManifestBody {
        refs: manifest.refs,
        new_packs: manifest.new_packs,
        predecessor_key_wrap: manifest.predecessor_key_wrap,
    })?;
    let body_key = derive_subkey(
        generation_key,
        &header.repository_root,
        header.generation,
        SubkeyKind::ManifestBody,
        0,
    )?;
    let body_ciphertext = seal_with_key(
        &body_key,
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
    {
        bail!("manifest header does not match its policy")
    }
    validate_recipient_set(&header, policy)?;
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
        ManifestAuthorization::Checkpoint => {
            bail!("checkpoint transitions are reserved but not implemented")
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

pub fn unwrap_generation_key(header: &ManifestHeader, key: &KeyFile) -> Result<SecretKey> {
    if key.repository_root != header.repository_root {
        bail!("key file belongs to a different repository")
    }
    let device_id = key.device_id()?;
    let envelope = header
        .generation_key_envelopes
        .iter()
        .find(|envelope| envelope.device_id == device_id)
        .context("device is not an active reader in this generation")?;
    let aad = generation_key_aad(
        &header.repository_root,
        header.generation,
        &header.policy_id,
        &device_id,
        &header.key_commitment,
    );
    let generation_key = key.unwrap_generation_key(
        &BASE64.decode(&envelope.encapsulated_key)?,
        &BASE64.decode(&envelope.ciphertext)?,
        &aad,
    )?;
    verify_key_commitment(&generation_key, &header.key_commitment)?;
    Ok(generation_key)
}

pub fn open_manifest(
    encrypted: &[u8],
    policy: &PolicyState,
    parent_policy: Option<&PolicyState>,
    generation_key: &[u8; 32],
) -> Result<Manifest> {
    let header = read_manifest_header(encrypted, policy, parent_policy)?;
    verify_key_commitment(generation_key, &header.key_commitment)?;
    let parsed = parse_envelope(encrypted)?;
    let body_key = derive_subkey(
        generation_key,
        &header.repository_root,
        header.generation,
        SubkeyKind::ManifestBody,
        0,
    )?;
    let body_bytes = open_with_key(
        &body_key,
        &parsed.body_ciphertext,
        &manifest_body_aad(&header.repository_root, header.generation),
    )?;
    let body: ManifestBody = serde_json::from_slice(&body_bytes).context("parse manifest body")?;
    let manifest = Manifest {
        format_version: header.format_version,
        repository_root: header.repository_root,
        generation: header.generation,
        previous: header.previous,
        policy_id: header.policy_id,
        policy_generation: header.policy_generation,
        authorization: header.authorization,
        total_pack_count: header.total_pack_count,
        refs: body.refs,
        new_packs: body.new_packs,
        predecessor_key_wrap: body.predecessor_key_wrap,
    };
    validate_pack_delta(&manifest)?;
    if (manifest.generation == 0) != manifest.predecessor_key_wrap.is_none() {
        bail!("manifest predecessor key link does not match its generation")
    }
    Ok(manifest)
}

pub fn wrap_predecessor_key(
    generation_key: &[u8; 32],
    previous_key: &[u8; 32],
    repository_root: &str,
    generation: u64,
    previous_manifest_id: &str,
) -> Result<String> {
    let link_key = derive_subkey(
        generation_key,
        repository_root,
        generation,
        SubkeyKind::PredecessorLink,
        0,
    )?;
    Ok(BASE64.encode(seal_with_key(
        &link_key,
        previous_key,
        &predecessor_link_aad(repository_root, generation, previous_manifest_id),
    )?))
}

pub fn unwrap_predecessor_key(
    generation_key: &[u8; 32],
    manifest: &Manifest,
    parent_header: &ManifestHeader,
) -> Result<SecretKey> {
    let previous_id = manifest
        .previous
        .as_deref()
        .context("genesis manifest has no predecessor key")?;
    let encrypted = manifest
        .predecessor_key_wrap
        .as_deref()
        .context("successor manifest is missing predecessor key link")?;
    if parent_header.generation + 1 != manifest.generation
        || parent_header.repository_root != manifest.repository_root
    {
        bail!("predecessor header does not match manifest generation")
    }
    let link_key = derive_subkey(
        generation_key,
        &manifest.repository_root,
        manifest.generation,
        SubkeyKind::PredecessorLink,
        0,
    )?;
    let plaintext = zeroize::Zeroizing::new(open_with_key(
        &link_key,
        &BASE64.decode(encrypted)?,
        &predecessor_link_aad(&manifest.repository_root, manifest.generation, previous_id),
    )?);
    let key: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid predecessor generation key length"))?;
    let key = zeroize::Zeroizing::new(key);
    verify_key_commitment(&key, &parent_header.key_commitment)?;
    Ok(key)
}

pub fn pack_aad(repository_root: &str, generation: u64, ordinal: u64) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee pack v3\0".to_vec();
    push_field(&mut aad, repository_root.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(&ordinal.to_le_bytes());
    aad
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
    {
        bail!("manifest does not match policy state")
    }
    Ok(())
}

fn validate_recipient_set(header: &ManifestHeader, policy: &PolicyState) -> Result<()> {
    let active: HashSet<_> = policy
        .body
        .devices
        .iter()
        .filter(|device| device.active() && device.roles.reader)
        .map(|device| device.public.device_id.as_str())
        .collect();
    let wrapped: HashSet<_> = header
        .generation_key_envelopes
        .iter()
        .map(|envelope| envelope.device_id.as_str())
        .collect();
    if wrapped.len() != header.generation_key_envelopes.len() || wrapped != active {
        bail!("generation key envelopes must match active readers exactly")
    }
    Ok(())
}

fn validate_pack_delta(manifest: &Manifest) -> Result<()> {
    let mut ids = HashSet::new();
    for (index, pack) in manifest.new_packs.iter().enumerate() {
        if pack.generation != manifest.generation || pack.ordinal != index as u64 {
            bail!("pack delta has a non-dense generation-local ordinal")
        }
        if !ids.insert(pack.id.as_str()) {
            bail!("pack delta contains a duplicate ciphertext id")
        }
    }
    Ok(())
}

fn manifest_signed_bytes(exact_header: &[u8], body_ciphertext: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(exact_header.len() + 32);
    bytes.extend_from_slice(exact_header);
    bytes.extend_from_slice(&Sha256::digest(body_ciphertext));
    bytes
}

fn generation_key_aad(
    root: &str,
    generation: u64,
    policy_id: &str,
    recipient_id: &str,
    commitment: &str,
) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee generation envelope v3\0".to_vec();
    push_field(&mut aad, root.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    push_field(&mut aad, policy_id.as_bytes());
    push_field(&mut aad, recipient_id.as_bytes());
    push_field(&mut aad, commitment.as_bytes());
    aad
}

fn manifest_body_aad(root: &str, generation: u64) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee manifest body v3\0".to_vec();
    push_field(&mut aad, root.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad
}

fn predecessor_link_aad(root: &str, generation: u64, previous_id: &str) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee predecessor link v3\0".to_vec();
    push_field(&mut aad, root.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    push_field(&mut aad, previous_id.as_bytes());
    aad
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_le_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PublicDevice, random_key};
    use crate::policy::{DeviceRecord, DeviceRoles};

    fn add_reader(owner: &KeyFile, parent: &PolicyState, reader: &KeyFile) -> PolicyState {
        let mut devices = parent.body.devices.clone();
        devices.push(DeviceRecord {
            public: reader.public_device().unwrap(),
            roles: DeviceRoles::collaborator(),
            revoked_at: None,
        });
        let (policy, _) = PolicyState::successor(parent, devices, owner).unwrap();
        policy.validate_successor(parent).unwrap();
        policy
    }

    #[test]
    fn predecessor_link_must_match_parent_commitment() {
        let owner = KeyFile::generate();
        let (policy, _) = PolicyState::genesis(&owner).unwrap();
        let parent_key = random_key();
        let parent = Manifest::genesis(owner.repository_root.clone(), &policy);
        let parent_bytes = seal_manifest(
            &owner,
            &policy,
            &parent_key,
            ManifestAuthorization::PolicyTransition,
            parent,
        )
        .unwrap();
        let parent_id = crate::crypto::object_id(&parent_bytes);
        let parent_header = read_manifest_header(&parent_bytes, &policy, None).unwrap();

        let child_key = random_key();
        let wrong_parent_key = random_key();
        let child = Manifest {
            format_version: FORMAT_VERSION,
            repository_root: owner.repository_root.clone(),
            generation: 1,
            previous: Some(parent_id.clone()),
            policy_id: policy.id.clone(),
            policy_generation: policy.body.generation,
            authorization: ManifestAuthorization::Writer,
            total_pack_count: 0,
            refs: BTreeMap::new(),
            new_packs: Vec::new(),
            predecessor_key_wrap: Some(
                wrap_predecessor_key(
                    &child_key,
                    &wrong_parent_key,
                    &owner.repository_root,
                    1,
                    &parent_id,
                )
                .unwrap(),
            ),
        };
        let child_bytes = seal_manifest(
            &owner,
            &policy,
            &child_key,
            ManifestAuthorization::Writer,
            child,
        )
        .unwrap();
        let opened = open_manifest(&child_bytes, &policy, None, &child_key).unwrap();
        assert!(unwrap_predecessor_key(&child_key, &opened, &parent_header).is_err());
    }

    #[test]
    fn every_validator_rejects_missing_or_duplicate_recipient_envelopes() {
        let owner = KeyFile::generate();
        let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (parent, _) = PolicyState::genesis(&owner).unwrap();
        let policy = add_reader(&owner, &parent, &reader);
        let generation_key = random_key();
        let manifest = Manifest {
            format_version: FORMAT_VERSION,
            repository_root: owner.repository_root.clone(),
            generation: 1,
            previous: Some("00".repeat(32)),
            policy_id: policy.id.clone(),
            policy_generation: policy.body.generation,
            authorization: ManifestAuthorization::PolicyTransition,
            total_pack_count: 0,
            refs: BTreeMap::new(),
            new_packs: Vec::new(),
            predecessor_key_wrap: Some(BASE64.encode([0_u8; 64])),
        };
        let bytes = seal_manifest(
            &owner,
            &policy,
            &generation_key,
            ManifestAuthorization::PolicyTransition,
            manifest,
        )
        .unwrap();
        let mut outer: ManifestEnvelope = serde_json::from_slice(&bytes).unwrap();
        let mut header: ManifestHeader =
            serde_json::from_slice(&BASE64.decode(&outer.header).unwrap()).unwrap();
        header.generation_key_envelopes.pop();
        outer.header = BASE64.encode(serde_json::to_vec(&header).unwrap());
        let missing = serde_json::to_vec(&outer).unwrap();
        assert!(read_manifest_header(&missing, &policy, Some(&parent)).is_err());

        let mut outer: ManifestEnvelope = serde_json::from_slice(&bytes).unwrap();
        let mut header: ManifestHeader =
            serde_json::from_slice(&BASE64.decode(&outer.header).unwrap()).unwrap();
        header
            .generation_key_envelopes
            .push(header.generation_key_envelopes[0].clone());
        outer.header = BASE64.encode(serde_json::to_vec(&header).unwrap());
        let duplicate = serde_json::to_vec(&outer).unwrap();
        assert!(read_manifest_header(&duplicate, &policy, Some(&parent)).is_err());
    }

    #[test]
    fn signed_extra_envelope_for_revoked_reader_is_rejected() {
        let owner = KeyFile::generate();
        let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (genesis, _) = PolicyState::genesis(&owner).unwrap();
        let with_reader = add_reader(&owner, &genesis, &reader);
        let mut devices = with_reader.body.devices.clone();
        devices
            .iter_mut()
            .find(|device| device.public.device_id == reader.device_id().unwrap())
            .unwrap()
            .revoked_at = Some(with_reader.body.generation + 1);
        let (revoked, _) = PolicyState::successor(&with_reader, devices, &owner).unwrap();
        revoked.validate_successor(&with_reader).unwrap();

        let generation_key = random_key();
        let manifest = Manifest {
            format_version: FORMAT_VERSION,
            repository_root: owner.repository_root.clone(),
            generation: 2,
            previous: Some("00".repeat(32)),
            policy_id: revoked.id.clone(),
            policy_generation: revoked.body.generation,
            authorization: ManifestAuthorization::PolicyTransition,
            total_pack_count: 0,
            refs: BTreeMap::new(),
            new_packs: Vec::new(),
            predecessor_key_wrap: Some(BASE64.encode([0_u8; 64])),
        };
        let bytes = seal_manifest(
            &owner,
            &revoked,
            &generation_key,
            ManifestAuthorization::PolicyTransition,
            manifest,
        )
        .unwrap();
        let mut outer: ManifestEnvelope = serde_json::from_slice(&bytes).unwrap();
        let mut header: ManifestHeader =
            serde_json::from_slice(&BASE64.decode(&outer.header).unwrap()).unwrap();
        let public = reader.public_device().unwrap();
        let aad = generation_key_aad(
            &header.repository_root,
            header.generation,
            &header.policy_id,
            &public.device_id,
            &header.key_commitment,
        );
        let (encapsulated, ciphertext) =
            wrap_generation_key(&public.wrapping_public_key, &generation_key, &aad).unwrap();
        header.generation_key_envelopes.push(GenerationKeyEnvelope {
            device_id: public.device_id,
            encapsulated_key: BASE64.encode(encapsulated),
            ciphertext: BASE64.encode(ciphertext),
        });
        header
            .generation_key_envelopes
            .sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let exact_header = serde_json::to_vec(&header).unwrap();
        let body_ciphertext = BASE64.decode(&outer.body_ciphertext).unwrap();
        outer.header = BASE64.encode(&exact_header);
        outer.signature = BASE64.encode(
            owner
                .sign_domain(
                    MANIFEST_SIGNATURE_DOMAIN,
                    &manifest_signed_bytes(&exact_header, &body_ciphertext),
                )
                .unwrap(),
        );
        let malicious = serde_json::to_vec(&outer).unwrap();
        let error = read_manifest_header(&malicious, &revoked, Some(&with_reader))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("must match active readers exactly"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn wrong_recipient_key_is_rejected_by_signed_commitment() {
        let owner = KeyFile::generate();
        let (policy, _) = PolicyState::genesis(&owner).unwrap();
        let intended = random_key();
        let wrong = random_key();
        let manifest = Manifest::genesis(owner.repository_root.clone(), &policy);
        let bytes = seal_manifest(
            &owner,
            &policy,
            &intended,
            ManifestAuthorization::PolicyTransition,
            manifest,
        )
        .unwrap();
        let mut outer: ManifestEnvelope = serde_json::from_slice(&bytes).unwrap();
        let mut header: ManifestHeader =
            serde_json::from_slice(&BASE64.decode(&outer.header).unwrap()).unwrap();
        let PublicDevice {
            wrapping_public_key,
            device_id,
            ..
        } = owner.public_device().unwrap();
        let aad = generation_key_aad(
            &header.repository_root,
            header.generation,
            &header.policy_id,
            &device_id,
            &header.key_commitment,
        );
        let (encapsulated, ciphertext) =
            wrap_generation_key(&wrapping_public_key, &wrong, &aad).unwrap();
        header.generation_key_envelopes = vec![GenerationKeyEnvelope {
            device_id,
            encapsulated_key: BASE64.encode(encapsulated),
            ciphertext: BASE64.encode(ciphertext),
        }];
        let exact_header = serde_json::to_vec(&header).unwrap();
        let body_ciphertext = BASE64.decode(&outer.body_ciphertext).unwrap();
        outer.header = BASE64.encode(&exact_header);
        outer.signature = BASE64.encode(
            owner
                .sign_domain(
                    MANIFEST_SIGNATURE_DOMAIN,
                    &manifest_signed_bytes(&exact_header, &body_ciphertext),
                )
                .unwrap(),
        );
        let malicious = serde_json::to_vec(&outer).unwrap();
        let verified = read_manifest_header(&malicious, &policy, None).unwrap();
        assert!(unwrap_generation_key(&verified, &owner).is_err());
    }
}
