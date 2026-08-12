use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::crypto::KeyFile;

pub const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackDescriptor {
    pub id: String,
    pub plaintext_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub repository_id: String,
    pub generation: u64,
    pub previous: Option<String>,
    pub refs: BTreeMap<String, String>,
    pub packs: Vec<PackDescriptor>,
}

impl Manifest {
    pub fn genesis(repository_id: String) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            repository_id,
            generation: 0,
            previous: None,
            refs: BTreeMap::new(),
            packs: Vec::new(),
        }
    }

    pub fn validate_successor(&self, previous_id: &str, previous: &Manifest) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            bail!("unsupported manifest format {}", self.format_version)
        }
        if self.repository_id != previous.repository_id {
            bail!("manifest repository id changed")
        }
        if self.generation != previous.generation + 1 {
            bail!("manifest generation is not consecutive")
        }
        if self.previous.as_deref() != Some(previous_id) {
            bail!("manifest previous pointer does not match")
        }
        if !self.packs.starts_with(&previous.packs) {
            bail!("manifest removed or rewrote pack inventory")
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct SignedManifest {
    writer_id: String,
    signature: String,
    manifest: Manifest,
}

pub fn seal_manifest(key: &KeyFile, manifest: Manifest) -> Result<Vec<u8>> {
    let canonical = serde_json::to_vec(&manifest)?;
    let signed = SignedManifest {
        writer_id: key.writer_id()?,
        signature: BASE64.encode(key.sign(&canonical)?),
        manifest,
    };
    key.seal(
        &serde_json::to_vec(&signed)?,
        b"git-remote-e2ee manifest v1",
    )
}

pub fn open_manifest(key: &KeyFile, encrypted: &[u8]) -> Result<Manifest> {
    let plaintext = key.open(encrypted, b"git-remote-e2ee manifest v1")?;
    let signed: SignedManifest =
        serde_json::from_slice(&plaintext).context("parse signed manifest")?;
    let canonical = serde_json::to_vec(&signed.manifest)?;
    let signature = BASE64.decode(signed.signature)?;
    key.verify(&canonical, &signature, &signed.writer_id)?;
    if signed.manifest.repository_id != key.repository_id {
        bail!("key file belongs to a different repository")
    }
    Ok(signed.manifest)
}
