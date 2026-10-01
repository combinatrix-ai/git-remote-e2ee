use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{
    HPKE_CIPHERTEXT_SIZE, HPKE_ENCAPSULATED_KEY_SIZE, KeyFile, SecretKey, SubkeyKind, commit_key,
    derive_subkey, dummy_generation_envelope, open_with_key, random_seed, seal_with_key,
    verify_domain, verify_key_commitment, wrap_generation_key_with_seed,
};
use crate::policy::PolicyState;

pub const FORMAT_VERSION: u32 = 5;
pub const MAX_GENERATION_ENVELOPES: usize = 4096;
const MIN_GENERATION_ENVELOPES: usize = 4;
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"git-remote-e2ee manifest v5\0";

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
    pub encapsulated_key: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvelopeAuditEntry {
    Recipient {
        device_id: String,
        encapsulation_seed: String,
    },
    Dummy,
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
    pub introduced_policy: Option<Vec<u8>>,
}

impl Manifest {
    pub fn genesis(repository_root: String, policy: &PolicyState, policy_bytes: Vec<u8>) -> Self {
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
            introduced_policy: Some(policy_bytes),
        }
    }

    pub fn validate_genesis(&self, policy: &PolicyState) -> Result<()> {
        validate_manifest_policy(self, policy)?;
        validate_introduced_policy(self, policy, true)?;
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
                validate_introduced_policy(self, selected_policy, false)?;
                if self.policy_id != previous.policy_id
                    || self.policy_generation != previous.policy_generation
                {
                    bail!("writer manifest changed policy state")
                }
            }
            ManifestAuthorization::PolicyTransition => {
                validate_introduced_policy(self, selected_policy, true)?;
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

/// The complete plaintext part of a v5 manifest. Device identities and policy
/// metadata are only present in the encrypted sealed header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestHeader {
    pub format_version: u32,
    pub repository_root: String,
    pub generation: u64,
    pub previous: Option<String>,
    pub key_commitment: String,
    pub generation_key_envelopes: Vec<GenerationKeyEnvelope>,
    pub body_digest: String,
    pub sealed_header_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedHeaderContent {
    policy_id: String,
    policy_generation: u64,
    signer_device_id: String,
    authorization: ManifestAuthorization,
    total_pack_count: u64,
    envelope_audit: Vec<EnvelopeAuditEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedHeaderEnvelope {
    content: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    refs: BTreeMap<String, String>,
    new_packs: Vec<PackDescriptor>,
    predecessor_key_wrap: Option<String>,
    introduced_policy: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEnvelope {
    header: String,
    sealed_header_ciphertext: String,
    body_ciphertext: String,
}

#[derive(Clone, Debug)]
pub struct OpenedManifest {
    pub(crate) header: ManifestHeader,
    pub(crate) manifest: Manifest,
    exact_header: Vec<u8>,
    exact_sealed_content: Vec<u8>,
    signature: Vec<u8>,
}

impl OpenedManifest {
    pub fn header(&self) -> &ManifestHeader {
        &self.header
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
}

pub fn seal_manifest(
    key: &KeyFile,
    policy: &PolicyState,
    generation_key: &[u8; 32],
    authorization: ManifestAuthorization,
    manifest: Manifest,
) -> Result<Vec<u8>> {
    validate_manifest_policy(&manifest, policy)?;
    if manifest.authorization != authorization {
        bail!("manifest authorization does not match its transition")
    }
    match authorization {
        ManifestAuthorization::Writer => validate_introduced_policy(&manifest, policy, false)?,
        ManifestAuthorization::PolicyTransition if manifest.generation == 0 => {
            validate_introduced_policy(&manifest, policy, true)?
        }
        ManifestAuthorization::PolicyTransition => {
            validate_introduced_policy(&manifest, policy, true)?
        }
        ManifestAuthorization::Checkpoint => {
            bail!("checkpoint transitions are reserved but not implemented")
        }
    }
    validate_pack_delta(&manifest)?;

    let commitment = commit_key(generation_key);
    let (generation_key_envelopes, envelope_audit) =
        build_envelopes(policy, &manifest, generation_key, &commitment)?;
    let body = serde_json::to_vec(&ManifestBody {
        refs: manifest.refs.clone(),
        new_packs: manifest.new_packs.clone(),
        predecessor_key_wrap: manifest.predecessor_key_wrap.clone(),
        introduced_policy: manifest
            .introduced_policy
            .as_deref()
            .map(|bytes| BASE64.encode(bytes)),
    })?;
    let body_key = derive_subkey(
        generation_key,
        &manifest.repository_root,
        manifest.generation,
        SubkeyKind::ManifestBody,
        0,
    )?;
    let body_ciphertext = seal_with_key(
        &body_key,
        &body,
        &manifest_body_aad(&manifest.repository_root, manifest.generation),
    )?;
    let body_digest = hex::encode(Sha256::digest(&body_ciphertext));

    let content = SealedHeaderContent {
        policy_id: manifest.policy_id.clone(),
        policy_generation: manifest.policy_generation,
        signer_device_id: key.device_id()?,
        authorization,
        total_pack_count: manifest.total_pack_count,
        envelope_audit,
    };
    let exact_sealed_content = serde_json::to_vec(&content)?;
    let header = ManifestHeader {
        format_version: manifest.format_version,
        repository_root: manifest.repository_root.clone(),
        generation: manifest.generation,
        previous: manifest.previous.clone(),
        key_commitment: commitment,
        generation_key_envelopes,
        body_digest,
        sealed_header_digest: hex::encode(Sha256::digest(&exact_sealed_content)),
    };
    validate_public_header(&header)?;
    validate_envelope_layout(&header)?;
    let exact_header = serde_json::to_vec(&header)?;
    let signed_bytes =
        manifest_signed_bytes(&exact_header, &exact_sealed_content, &header.body_digest);
    let sealed = SealedHeaderEnvelope {
        content: BASE64.encode(&exact_sealed_content),
        signature: BASE64.encode(key.sign_domain(MANIFEST_SIGNATURE_DOMAIN, &signed_bytes)?),
    };
    let sealed_bytes = serde_json::to_vec(&sealed)?;
    let sealed_key = derive_subkey(
        generation_key,
        &header.repository_root,
        header.generation,
        SubkeyKind::SealedHeader,
        0,
    )?;
    let sealed_header_ciphertext = seal_with_key(&sealed_key, &sealed_bytes, &exact_header)?;
    Ok(serde_json::to_vec(&ManifestEnvelope {
        header: BASE64.encode(exact_header),
        sealed_header_ciphertext: BASE64.encode(sealed_header_ciphertext),
        body_ciphertext: BASE64.encode(body_ciphertext),
    })?)
}

pub fn peek_manifest_header(encrypted: &[u8]) -> Result<ManifestHeader> {
    let envelope: ManifestEnvelope =
        serde_json::from_slice(encrypted).context("parse manifest envelope")?;
    let exact_header = BASE64
        .decode(envelope.header)
        .context("decode manifest header")?;
    let header: ManifestHeader =
        serde_json::from_slice(&exact_header).context("parse manifest header")?;
    validate_public_header(&header)?;
    Ok(header)
}

pub fn unwrap_generation_key(header: &ManifestHeader, key: &KeyFile) -> Result<SecretKey> {
    if key.repository_root != header.repository_root {
        bail!("key file belongs to a different repository")
    }
    validate_public_header(header)?;
    let device_id = key.device_id()?;
    for envelope in &header.generation_key_envelopes {
        let Ok(encapsulated_key) = BASE64.decode(&envelope.encapsulated_key) else {
            continue;
        };
        let Ok(ciphertext) = BASE64.decode(&envelope.ciphertext) else {
            continue;
        };
        let aad = generation_key_aad(
            &header.repository_root,
            header.generation,
            &device_id,
            &header.key_commitment,
        );
        if let Ok(generation_key) = key.unwrap_generation_key(&encapsulated_key, &ciphertext, &aad)
            && verify_key_commitment(&generation_key, &header.key_commitment).is_ok()
        {
            return Ok(generation_key);
        }
    }
    bail!(
        "device is not an active reader of the current generation (revoked, never added, or envelope malformed)"
    )
}

pub fn open_manifest(encrypted: &[u8], generation_key: &[u8; 32]) -> Result<OpenedManifest> {
    let envelope: ManifestEnvelope =
        serde_json::from_slice(encrypted).context("parse manifest envelope")?;
    let exact_header = BASE64
        .decode(envelope.header)
        .context("decode manifest header")?;
    let header: ManifestHeader =
        serde_json::from_slice(&exact_header).context("parse manifest header")?;
    validate_public_header(&header)?;
    verify_key_commitment(generation_key, &header.key_commitment)?;
    let sealed_header_ciphertext = BASE64
        .decode(envelope.sealed_header_ciphertext)
        .context("decode sealed manifest header")?;
    let body_ciphertext = BASE64
        .decode(envelope.body_ciphertext)
        .context("decode manifest body")?;
    if hex::encode(Sha256::digest(&body_ciphertext)) != header.body_digest {
        bail!("manifest body digest mismatch")
    }

    let sealed_key = derive_subkey(
        generation_key,
        &header.repository_root,
        header.generation,
        SubkeyKind::SealedHeader,
        0,
    )?;
    let sealed_bytes = open_with_key(&sealed_key, &sealed_header_ciphertext, &exact_header)
        .context("open sealed manifest header")?;
    let sealed: SealedHeaderEnvelope =
        serde_json::from_slice(&sealed_bytes).context("parse sealed manifest header")?;
    let exact_sealed_content = BASE64
        .decode(sealed.content)
        .context("decode sealed manifest content")?;
    if hex::encode(Sha256::digest(&exact_sealed_content)) != header.sealed_header_digest {
        bail!("sealed manifest header digest mismatch")
    }
    let content: SealedHeaderContent =
        serde_json::from_slice(&exact_sealed_content).context("parse sealed manifest content")?;
    if serde_json::to_vec(&content)? != exact_sealed_content {
        bail!("sealed manifest content is not canonically encoded")
    }
    let signature = BASE64
        .decode(sealed.signature)
        .context("decode manifest signature")?;

    let body_key = derive_subkey(
        generation_key,
        &header.repository_root,
        header.generation,
        SubkeyKind::ManifestBody,
        0,
    )?;
    let body_bytes = open_with_key(
        &body_key,
        &body_ciphertext,
        &manifest_body_aad(&header.repository_root, header.generation),
    )?;
    let body: ManifestBody = serde_json::from_slice(&body_bytes).context("parse manifest body")?;
    let introduced_policy = body
        .introduced_policy
        .map(|encoded| BASE64.decode(encoded).context("decode introduced policy"))
        .transpose()?;
    let manifest = Manifest {
        format_version: header.format_version,
        repository_root: header.repository_root.clone(),
        generation: header.generation,
        previous: header.previous.clone(),
        policy_id: content.policy_id,
        policy_generation: content.policy_generation,
        authorization: content.authorization,
        total_pack_count: content.total_pack_count,
        refs: body.refs,
        new_packs: body.new_packs,
        predecessor_key_wrap: body.predecessor_key_wrap,
        introduced_policy,
    };
    validate_pack_delta(&manifest)?;
    if (manifest.generation == 0) != manifest.predecessor_key_wrap.is_none() {
        bail!("manifest predecessor key link does not match its generation")
    }
    if manifest.generation == 0 && manifest.previous.is_some()
        || manifest.generation > 0 && manifest.previous.is_none()
    {
        bail!("manifest previous pointer does not match its generation")
    }
    Ok(OpenedManifest {
        header,
        manifest,
        exact_header,
        exact_sealed_content,
        signature,
    })
}

pub fn verify_manifest(
    opened: &OpenedManifest,
    selected_policy: &PolicyState,
    parent_policy: Option<&PolicyState>,
    generation_key: &[u8; 32],
) -> Result<()> {
    let manifest = &opened.manifest;
    if manifest.format_version != FORMAT_VERSION
        || manifest.repository_root != selected_policy.body.repository_root
        || manifest.policy_id != selected_policy.id
        || manifest.policy_generation != selected_policy.body.generation
    {
        bail!("manifest does not match policy state")
    }
    validate_public_header(&opened.header)?;
    validate_envelope_layout(&opened.header)?;
    if manifest.format_version != opened.header.format_version
        || manifest.repository_root != opened.header.repository_root
        || manifest.generation != opened.header.generation
        || manifest.previous != opened.header.previous
    {
        bail!("sealed manifest metadata does not match its plaintext header")
    }
    let content: SealedHeaderContent = serde_json::from_slice(&opened.exact_sealed_content)
        .context("parse sealed manifest content")?;
    if serde_json::to_vec(&content)? != opened.exact_sealed_content
        || content.policy_id != manifest.policy_id
        || content.policy_generation != manifest.policy_generation
        || content.authorization != manifest.authorization
        || content.total_pack_count != manifest.total_pack_count
    {
        bail!("opened manifest fields do not match the signed sealed header")
    }
    let authorizing = match content.authorization {
        ManifestAuthorization::Writer => selected_policy
            .device(&content.signer_device_id)
            .filter(|device| device.active() && device.roles.writer)
            .context("manifest was not signed by an active writer")?,
        ManifestAuthorization::PolicyTransition => {
            let authorizing = parent_policy.unwrap_or(selected_policy);
            authorizing
                .device(&content.signer_device_id)
                .filter(|device| device.active() && device.roles.administrator)
                .context("policy transition manifest was not signed by a parent administrator")?
        }
        ManifestAuthorization::Checkpoint => {
            bail!("checkpoint transitions are reserved but not implemented")
        }
    };
    verify_domain(
        &authorizing.public.signing_public_key,
        MANIFEST_SIGNATURE_DOMAIN,
        &manifest_signed_bytes(
            &opened.exact_header,
            &opened.exact_sealed_content,
            &opened.header.body_digest,
        ),
        &opened.signature,
    )?;
    validate_envelope_audit(
        &opened.header,
        &content.envelope_audit,
        selected_policy,
        generation_key,
    )
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
    let mut aad = b"git-remote-e2ee pack v5\0".to_vec();
    push_field(&mut aad, repository_root.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(&ordinal.to_le_bytes());
    aad
}

fn build_envelopes(
    policy: &PolicyState,
    manifest: &Manifest,
    generation_key: &[u8; 32],
    commitment: &str,
) -> Result<(Vec<GenerationKeyEnvelope>, Vec<EnvelopeAuditEntry>)> {
    let readers: Vec<_> = policy
        .body
        .devices
        .iter()
        .filter(|device| device.active() && device.roles.reader)
        .collect();
    if readers.is_empty() {
        bail!("policy has no active readers")
    }
    let count = readers
        .len()
        .checked_next_power_of_two()
        .context("active reader count is too large")?
        .max(MIN_GENERATION_ENVELOPES);
    if count > MAX_GENERATION_ENVELOPES {
        bail!("padded generation envelope count exceeds {MAX_GENERATION_ENVELOPES}")
    }

    let mut pairs = Vec::with_capacity(count);
    for device in readers {
        let seed = random_seed();
        let aad = generation_key_aad(
            &manifest.repository_root,
            manifest.generation,
            &device.public.device_id,
            commitment,
        );
        let (encapsulated, ciphertext) = wrap_generation_key_with_seed(
            &device.public.wrapping_public_key,
            generation_key,
            &aad,
            &seed,
        )?;
        pairs.push((
            encapsulated.clone(),
            GenerationKeyEnvelope {
                encapsulated_key: BASE64.encode(&encapsulated),
                ciphertext: BASE64.encode(ciphertext),
            },
            EnvelopeAuditEntry::Recipient {
                device_id: device.public.device_id.clone(),
                encapsulation_seed: BASE64.encode(seed),
            },
        ));
    }
    while pairs.len() < count {
        let (encapsulated, ciphertext) = dummy_generation_envelope()?;
        pairs.push((
            encapsulated.clone(),
            GenerationKeyEnvelope {
                encapsulated_key: BASE64.encode(encapsulated),
                ciphertext: BASE64.encode(ciphertext),
            },
            EnvelopeAuditEntry::Dummy,
        ));
    }
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    let mut envelopes = Vec::with_capacity(count);
    let mut audit = Vec::with_capacity(count);
    for (_, envelope, entry) in pairs {
        envelopes.push(envelope);
        audit.push(entry);
    }
    Ok((envelopes, audit))
}

fn validate_envelope_audit(
    header: &ManifestHeader,
    audit: &[EnvelopeAuditEntry],
    policy: &PolicyState,
    generation_key: &[u8; 32],
) -> Result<()> {
    if audit.len() != header.generation_key_envelopes.len() {
        bail!("envelope audit count does not match the envelope list")
    }
    let active: HashSet<_> = policy
        .body
        .devices
        .iter()
        .filter(|device| device.active() && device.roles.reader)
        .map(|device| device.public.device_id.as_str())
        .collect();
    let mut audited = HashSet::with_capacity(audit.len());
    for (envelope, entry) in header.generation_key_envelopes.iter().zip(audit) {
        let EnvelopeAuditEntry::Recipient {
            device_id,
            encapsulation_seed,
        } = entry
        else {
            continue;
        };
        if !active.contains(device_id.as_str()) {
            bail!("envelope audit names a device that is not an active reader")
        }
        if !audited.insert(device_id.as_str()) {
            bail!("envelope audit contains a duplicate reader")
        }
        let seed: [u8; 32] = BASE64
            .decode(encapsulation_seed)
            .context("decode envelope audit seed")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid envelope audit seed length"))?;
        let recipient = policy
            .device(device_id)
            .context("envelope audit names an unknown device")?;
        let aad = generation_key_aad(
            &header.repository_root,
            header.generation,
            device_id,
            &header.key_commitment,
        );
        let (encapsulated, ciphertext) = wrap_generation_key_with_seed(
            &recipient.public.wrapping_public_key,
            generation_key,
            &aad,
            &seed,
        )?;
        if BASE64.encode(encapsulated) != envelope.encapsulated_key
            || BASE64.encode(ciphertext) != envelope.ciphertext
        {
            bail!("generation envelope does not match its sealed audit entry")
        }
    }
    if audited != active {
        bail!("envelope audit must match active readers exactly")
    }
    Ok(())
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

fn validate_introduced_policy(
    manifest: &Manifest,
    selected_policy: &PolicyState,
    should_introduce: bool,
) -> Result<()> {
    match (&manifest.introduced_policy, should_introduce) {
        (Some(bytes), true) => {
            let policy = PolicyState::parse(bytes).context("parse introduced policy")?;
            if policy.id != selected_policy.id {
                bail!("manifest introduced policy id does not match its sealed header")
            }
        }
        (None, false) => {}
        (Some(_), false) => bail!("ordinary manifest unexpectedly introduces a policy"),
        (None, true) => bail!("policy transition manifest is missing its introduced policy"),
    }
    Ok(())
}

fn validate_public_header(header: &ManifestHeader) -> Result<()> {
    if header.format_version != FORMAT_VERSION {
        bail!("unsupported manifest format {}", header.format_version)
    }
    if header.repository_root.len() != 64
        || !header
            .repository_root
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("invalid manifest repository root")
    }
    if header.key_commitment.len() != 64
        || !header
            .key_commitment
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("invalid generation key commitment")
    }
    if header.body_digest.len() != 64
        || !header
            .body_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || header.sealed_header_digest.len() != 64
        || !header
            .sealed_header_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("invalid manifest part digest")
    }
    let count = header.generation_key_envelopes.len();
    if !(MIN_GENERATION_ENVELOPES..=MAX_GENERATION_ENVELOPES).contains(&count)
        || !count.is_power_of_two()
    {
        bail!("invalid padded generation envelope count")
    }
    Ok(())
}

fn validate_envelope_layout(header: &ManifestHeader) -> Result<()> {
    let mut previous: Option<Vec<u8>> = None;
    for envelope in &header.generation_key_envelopes {
        let encapsulated = BASE64
            .decode(&envelope.encapsulated_key)
            .context("decode HPKE encapsulated key")?;
        let ciphertext = BASE64
            .decode(&envelope.ciphertext)
            .context("decode HPKE ciphertext")?;
        if encapsulated.len() != HPKE_ENCAPSULATED_KEY_SIZE
            || ciphertext.len() != HPKE_CIPHERTEXT_SIZE
        {
            bail!("invalid generation envelope length")
        }
        if previous
            .as_ref()
            .is_some_and(|prior| prior >= &encapsulated)
        {
            bail!("generation envelopes are not sorted by encapsulated-key bytes")
        }
        previous = Some(encapsulated);
    }
    Ok(())
}

fn validate_pack_delta(manifest: &Manifest) -> Result<()> {
    let mut ids = HashSet::new();
    for (index, pack) in manifest.new_packs.iter().enumerate() {
        if pack.generation != manifest.generation || pack.ordinal != index as u64 {
            bail!("pack delta has a non-dense generation-local ordinal")
        }
        if pack.plaintext_size == 0 {
            bail!("pack plaintext size must be nonzero")
        }
        if !ids.insert(pack.id.as_str()) {
            bail!("pack delta contains a duplicate ciphertext id")
        }
    }
    Ok(())
}

fn manifest_signed_bytes(exact_header: &[u8], exact_content: &[u8], body_digest: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(exact_header.len() + exact_content.len() + 72);
    push_field(&mut bytes, exact_header);
    push_field(&mut bytes, exact_content);
    push_field(&mut bytes, body_digest.as_bytes());
    bytes
}

fn generation_key_aad(
    root: &str,
    generation: u64,
    recipient_id: &str,
    commitment: &str,
) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee generation envelope v5\0".to_vec();
    push_field(&mut aad, root.as_bytes());
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    push_field(&mut aad, commitment.as_bytes());
    push_field(&mut aad, recipient_id.as_bytes());
    aad
}

fn manifest_body_aad(root: &str, generation: u64) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee manifest body v5\0".to_vec();
    push_field(&mut aad, root.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad
}

fn predecessor_link_aad(root: &str, generation: u64, previous_id: &str) -> Vec<u8> {
    let mut aad = b"git-remote-e2ee predecessor link v5\0".to_vec();
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
    use crate::crypto::{KeyFile, open_with_key, random_key};
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

    fn manifest_for(
        policy: &PolicyState,
        generation: u64,
        auth: ManifestAuthorization,
    ) -> Manifest {
        Manifest {
            format_version: FORMAT_VERSION,
            repository_root: policy.body.repository_root.clone(),
            generation,
            previous: (generation > 0).then(|| "11".repeat(32)),
            policy_id: policy.id.clone(),
            policy_generation: policy.body.generation,
            authorization: auth,
            total_pack_count: 0,
            refs: BTreeMap::new(),
            new_packs: Vec::new(),
            predecessor_key_wrap: (generation > 0).then(|| BASE64.encode([7_u8; 64])),
            introduced_policy: None,
        }
    }

    fn rewrite_signed_manifest(
        encrypted: &[u8],
        signer: &KeyFile,
        generation_key: &[u8; 32],
        edit: impl FnOnce(&mut ManifestHeader, &mut SealedHeaderContent),
    ) -> Vec<u8> {
        let mut envelope: ManifestEnvelope = serde_json::from_slice(encrypted).unwrap();
        let mut header_bytes = BASE64.decode(&envelope.header).unwrap();
        let mut header: ManifestHeader = serde_json::from_slice(&header_bytes).unwrap();
        let sealed_ciphertext = BASE64.decode(&envelope.sealed_header_ciphertext).unwrap();
        let sealed_key = derive_subkey(
            generation_key,
            &header.repository_root,
            header.generation,
            SubkeyKind::SealedHeader,
            0,
        )
        .unwrap();
        let sealed_bytes = open_with_key(&sealed_key, &sealed_ciphertext, &header_bytes).unwrap();
        let mut sealed: SealedHeaderEnvelope = serde_json::from_slice(&sealed_bytes).unwrap();
        let mut content: SealedHeaderContent =
            serde_json::from_slice(&BASE64.decode(&sealed.content).unwrap()).unwrap();
        edit(&mut header, &mut content);
        let exact_content = serde_json::to_vec(&content).unwrap();
        header.sealed_header_digest = hex::encode(Sha256::digest(&exact_content));
        header_bytes = serde_json::to_vec(&header).unwrap();
        let body_ciphertext = BASE64.decode(&envelope.body_ciphertext).unwrap();
        let signed = manifest_signed_bytes(&header_bytes, &exact_content, &header.body_digest);
        sealed.content = BASE64.encode(&exact_content);
        sealed.signature = BASE64.encode(
            signer
                .sign_domain(MANIFEST_SIGNATURE_DOMAIN, &signed)
                .unwrap(),
        );
        let sealed_bytes = serde_json::to_vec(&sealed).unwrap();
        envelope.header = BASE64.encode(&header_bytes);
        envelope.sealed_header_ciphertext =
            BASE64.encode(seal_with_key(&sealed_key, &sealed_bytes, &header_bytes).unwrap());
        envelope.body_ciphertext = BASE64.encode(body_ciphertext);
        serde_json::to_vec(&envelope).unwrap()
    }

    fn writer_manifest(
        signer: &KeyFile,
        policy: &PolicyState,
        generation_key: &[u8; 32],
    ) -> Vec<u8> {
        let manifest = manifest_for(policy, 2, ManifestAuthorization::Writer);
        seal_manifest(
            signer,
            policy,
            generation_key,
            ManifestAuthorization::Writer,
            manifest,
        )
        .unwrap()
    }

    #[test]
    fn anonymous_envelopes_are_padded_and_open_by_trial_decryption() {
        let owner = KeyFile::generate();
        let reader_a = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let reader_b = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (genesis, genesis_bytes) = PolicyState::genesis(&owner).unwrap();
        let mut devices = genesis.body.devices.clone();
        for reader in [&reader_a, &reader_b] {
            devices.push(DeviceRecord {
                public: reader.public_device().unwrap(),
                roles: DeviceRoles::collaborator(),
                revoked_at: None,
            });
        }
        let (policy, _) = PolicyState::successor(&genesis, devices, &owner).unwrap();
        let (policy5, _policy5_bytes) =
            PolicyState::successor(&policy, policy.body.devices.clone(), &owner).unwrap();
        let mut one_reader = manifest_for(&genesis, 0, ManifestAuthorization::PolicyTransition);
        one_reader.introduced_policy = Some(genesis_bytes);
        let bytes = seal_manifest(
            &owner,
            &genesis,
            &random_key(),
            ManifestAuthorization::PolicyTransition,
            one_reader,
        )
        .unwrap();
        let header = peek_manifest_header(&bytes).unwrap();
        assert_eq!(header.generation_key_envelopes.len(), 4);
        let key = unwrap_generation_key(&header, &owner).unwrap();
        let opened = open_manifest(&bytes, &key).unwrap();
        verify_manifest(&opened, &genesis, None, &key).unwrap();

        let mut five_readers_devices = policy5.body.devices.clone();
        for _ in 0..2 {
            let extra = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
            five_readers_devices.push(DeviceRecord {
                public: extra.public_device().unwrap(),
                roles: DeviceRoles::collaborator(),
                revoked_at: None,
            });
        }
        let (five_readers, five_readers_bytes) =
            PolicyState::successor(&policy5, five_readers_devices, &owner).unwrap();
        let mut many = manifest_for(&five_readers, 4, ManifestAuthorization::PolicyTransition);
        many.previous = Some("22".repeat(32));
        many.predecessor_key_wrap = Some(BASE64.encode([8_u8; 64]));
        many.introduced_policy = Some(five_readers_bytes);
        let many_bytes = seal_manifest(
            &owner,
            &five_readers,
            &random_key(),
            ManifestAuthorization::PolicyTransition,
            many,
        )
        .unwrap();
        assert_eq!(
            peek_manifest_header(&many_bytes)
                .unwrap()
                .generation_key_envelopes
                .len(),
            8
        );
    }

    #[test]
    fn predecessor_link_must_match_parent_commitment() {
        let owner = KeyFile::generate();
        let (policy, policy_bytes) = PolicyState::genesis(&owner).unwrap();
        let parent_key = random_key();
        let parent = Manifest::genesis(owner.repository_root.clone(), &policy, policy_bytes);
        let parent_bytes = seal_manifest(
            &owner,
            &policy,
            &parent_key,
            ManifestAuthorization::PolicyTransition,
            parent,
        )
        .unwrap();
        let parent_id = crate::crypto::object_id(&parent_bytes);
        let parent_header = peek_manifest_header(&parent_bytes).unwrap();

        let child_key = random_key();
        let wrong_parent_key = random_key();
        let mut child = manifest_for(&policy, 1, ManifestAuthorization::Writer);
        child.previous = Some(parent_id.clone());
        child.predecessor_key_wrap = Some(
            wrap_predecessor_key(
                &child_key,
                &wrong_parent_key,
                &owner.repository_root,
                1,
                &parent_id,
            )
            .unwrap(),
        );
        let child_bytes = seal_manifest(
            &owner,
            &policy,
            &child_key,
            ManifestAuthorization::Writer,
            child,
        )
        .unwrap();
        let opened = open_manifest(&child_bytes, &child_key).unwrap();
        assert!(unwrap_predecessor_key(&child_key, &opened.manifest, &parent_header).is_err());
    }

    #[test]
    fn malicious_writer_cannot_replace_a_reader_envelope_with_garbage() {
        let owner = KeyFile::generate();
        let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (genesis, _) = PolicyState::genesis(&owner).unwrap();
        let policy = add_reader(&owner, &genesis, &reader);
        let generation_key = random_key();
        let valid = writer_manifest(&reader, &policy, &generation_key);
        let corrupted = rewrite_signed_manifest(
            &valid,
            &reader,
            &generation_key,
            |header, audit| {
                let index = audit
                .envelope_audit
                .iter()
                .position(|entry| matches!(entry, EnvelopeAuditEntry::Recipient { device_id, .. } if device_id == &reader.device_id().unwrap()))
                .unwrap();
                header.generation_key_envelopes[index].ciphertext =
                    BASE64.encode([0_u8; HPKE_CIPHERTEXT_SIZE]);
            },
        );
        let header = peek_manifest_header(&corrupted).unwrap();
        let owner_key = unwrap_generation_key(&header, &owner).unwrap();
        assert_eq!(*owner_key, *generation_key);
        let opened = open_manifest(&corrupted, &owner_key).unwrap();
        let error = verify_manifest(&opened, &policy, None, &owner_key)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match its sealed audit entry"));
    }

    #[test]
    fn reader_only_device_cannot_sign_an_ordinary_manifest() {
        let owner = KeyFile::generate();
        let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (genesis, _) = PolicyState::genesis(&owner).unwrap();
        let mut devices = genesis.body.devices.clone();
        devices.push(DeviceRecord {
            public: reader.public_device().unwrap(),
            roles: DeviceRoles::reader(),
            revoked_at: None,
        });
        let (policy, _) = PolicyState::successor(&genesis, devices, &owner).unwrap();
        let generation_key = random_key();

        // seal_manifest can construct a cryptographically valid signature from
        // any key. Verification must still enforce the signer's policy role.
        let encrypted = writer_manifest(&reader, &policy, &generation_key);
        let opened = open_manifest(&encrypted, &generation_key).unwrap();
        let error = verify_manifest(&opened, &policy, None, &generation_key)
            .unwrap_err()
            .to_string();
        assert!(error.contains("manifest was not signed by an active writer"));
    }

    #[test]
    fn reader_trials_all_envelopes_and_reports_inactive_membership_clearly() {
        let owner = KeyFile::generate();
        let outsider = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (policy, bytes) = PolicyState::genesis(&owner).unwrap();
        let manifest = Manifest::genesis(owner.repository_root.clone(), &policy, bytes);
        let encrypted = seal_manifest(
            &owner,
            &policy,
            &random_key(),
            ManifestAuthorization::PolicyTransition,
            manifest,
        )
        .unwrap();
        let error = unwrap_generation_key(&peek_manifest_header(&encrypted).unwrap(), &outsider)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not an active reader of the current generation"));
    }

    #[test]
    fn head_envelope_list_is_bounded_before_trial_decryption() {
        let owner = KeyFile::generate();
        let header = ManifestHeader {
            format_version: FORMAT_VERSION,
            repository_root: owner.repository_root.clone(),
            generation: 0,
            previous: None,
            key_commitment: "00".repeat(32),
            generation_key_envelopes: vec![
                GenerationKeyEnvelope {
                    encapsulated_key: String::new(),
                    ciphertext: String::new(),
                };
                MAX_GENERATION_ENVELOPES * 2
            ],
            body_digest: "11".repeat(32),
            sealed_header_digest: "22".repeat(32),
        };
        let error = unwrap_generation_key(&header, &owner)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid padded generation envelope count"));
    }

    #[test]
    fn audit_rejects_missing_duplicate_extra_and_revoked_reader_entries() {
        let owner = KeyFile::generate();
        let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (parent, _) = PolicyState::genesis(&owner).unwrap();
        let policy = add_reader(&owner, &parent, &reader);
        let generation_key = random_key();
        let valid = writer_manifest(&owner, &policy, &generation_key);
        let (real_indices, dummy_index) = {
            let opened = open_manifest(&valid, &generation_key).unwrap();
            let outer: ManifestEnvelope = serde_json::from_slice(&valid).unwrap();
            let header: ManifestHeader =
                serde_json::from_slice(&BASE64.decode(outer.header).unwrap()).unwrap();
            let sealed_ciphertext = BASE64.decode(outer.sealed_header_ciphertext).unwrap();
            let key = derive_subkey(
                &generation_key,
                &header.repository_root,
                header.generation,
                SubkeyKind::SealedHeader,
                0,
            )
            .unwrap();
            let opened_sealed = open_with_key(
                &key,
                &sealed_ciphertext,
                &serde_json::to_vec(&header).unwrap(),
            )
            .unwrap();
            let sealed: SealedHeaderEnvelope = serde_json::from_slice(&opened_sealed).unwrap();
            let content: SealedHeaderContent =
                serde_json::from_slice(&BASE64.decode(sealed.content).unwrap()).unwrap();
            let real = content
                .envelope_audit
                .iter()
                .enumerate()
                .filter(|(_, entry)| matches!(entry, EnvelopeAuditEntry::Recipient { .. }))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let dummy = content
                .envelope_audit
                .iter()
                .position(|entry| matches!(entry, EnvelopeAuditEntry::Dummy))
                .unwrap();
            assert_eq!(opened.manifest.policy_id, policy.id);
            (real, dummy)
        };
        let missing = rewrite_signed_manifest(&valid, &owner, &generation_key, |_, audit| {
            audit.envelope_audit.pop();
        });
        assert!(
            verify_manifest(
                &open_manifest(&missing, &generation_key).unwrap(),
                &policy,
                None,
                &generation_key
            )
            .is_err()
        );

        let duplicate = rewrite_signed_manifest(&valid, &owner, &generation_key, |_, audit| {
            let duplicate_entry = audit.envelope_audit[real_indices[0]].clone();
            audit.envelope_audit[real_indices[1]] = duplicate_entry;
        });
        assert!(
            verify_manifest(
                &open_manifest(&duplicate, &generation_key).unwrap(),
                &policy,
                None,
                &generation_key
            )
            .is_err()
        );

        let extra = rewrite_signed_manifest(&valid, &owner, &generation_key, |_, audit| {
            audit.envelope_audit[dummy_index] = EnvelopeAuditEntry::Recipient {
                device_id: "ff".repeat(32),
                encapsulation_seed: BASE64.encode([0_u8; 32]),
            };
        });
        assert!(
            verify_manifest(
                &open_manifest(&extra, &generation_key).unwrap(),
                &policy,
                None,
                &generation_key
            )
            .is_err()
        );

        let wrong_seed = rewrite_signed_manifest(&valid, &owner, &generation_key, |_, audit| {
            let EnvelopeAuditEntry::Recipient {
                encapsulation_seed, ..
            } = &mut audit.envelope_audit[real_indices[1]]
            else {
                unreachable!()
            };
            let mut seed: [u8; 32] = BASE64
                .decode(encapsulation_seed.as_str())
                .unwrap()
                .try_into()
                .unwrap();
            seed[0] ^= 1;
            *encapsulation_seed = BASE64.encode(seed);
        });
        assert!(
            verify_manifest(
                &open_manifest(&wrong_seed, &generation_key).unwrap(),
                &policy,
                None,
                &generation_key
            )
            .is_err()
        );

        let mut devices = policy.body.devices.clone();
        devices
            .iter_mut()
            .find(|device| device.public.device_id == reader.device_id().unwrap())
            .unwrap()
            .revoked_at = Some(2);
        let (revoked, _) = PolicyState::successor(&policy, devices, &owner).unwrap();
        let revoked_entry = rewrite_signed_manifest(&valid, &owner, &generation_key, |_, audit| {
            audit.policy_id = revoked.id.clone();
            audit.policy_generation = revoked.body.generation;
        });
        assert!(
            verify_manifest(
                &open_manifest(&revoked_entry, &generation_key).unwrap(),
                &revoked,
                None,
                &generation_key
            )
            .is_err()
        );
    }
}
