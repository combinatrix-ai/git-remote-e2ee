use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    KeyFile, PublicDevice, object_id, repository_root_for_device, validate_public_device,
    verify_domain, wrap_epoch_key,
};

pub const POLICY_FORMAT_VERSION: u32 = 1;
const POLICY_SIGNATURE_DOMAIN: &[u8] = b"git-remote-e2ee policy v2\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRoles {
    pub reader: bool,
    pub writer: bool,
    pub administrator: bool,
}

impl DeviceRoles {
    pub fn owner() -> Self {
        Self {
            reader: true,
            writer: true,
            administrator: true,
        }
    }

    pub fn collaborator() -> Self {
        Self {
            reader: true,
            writer: true,
            administrator: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    #[serde(flatten)]
    pub public: PublicDevice,
    pub roles: DeviceRoles,
    pub revoked_at: Option<u64>,
}

impl DeviceRecord {
    pub fn active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochWrap {
    pub device_id: String,
    pub encapsulated_key: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBody {
    pub format_version: u32,
    pub repository_root: String,
    pub generation: u64,
    pub previous: Option<String>,
    pub epoch: u64,
    pub admin_threshold: u32,
    pub devices: Vec<DeviceRecord>,
    pub epoch_wraps: Vec<EpochWrap>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignature {
    pub device_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyObject {
    body: String,
    signatures: Vec<PolicySignature>,
}

#[derive(Clone, Debug)]
pub struct PolicyState {
    pub id: String,
    pub body: PolicyBody,
    exact_body: Vec<u8>,
    signatures: Vec<PolicySignature>,
}

impl PolicyState {
    pub fn genesis(key: &KeyFile) -> Result<(Self, [u8; 32], Vec<u8>)> {
        let epoch_key = crate::crypto::random_key();
        let public = key.public_device()?;
        let body = PolicyBody {
            format_version: POLICY_FORMAT_VERSION,
            repository_root: key.repository_root.clone(),
            generation: 0,
            previous: None,
            epoch: 0,
            admin_threshold: 1,
            devices: vec![DeviceRecord {
                public,
                roles: DeviceRoles::owner(),
                revoked_at: None,
            }],
            epoch_wraps: Vec::new(),
        };
        Self::create(body, &epoch_key, key)
    }

    pub fn successor(
        parent: &PolicyState,
        mut devices: Vec<DeviceRecord>,
        epoch: u64,
        epoch_key: &[u8; 32],
        signer: &KeyFile,
    ) -> Result<(Self, Vec<u8>)> {
        devices.sort_by(|a, b| a.public.device_id.cmp(&b.public.device_id));
        let body = PolicyBody {
            format_version: POLICY_FORMAT_VERSION,
            repository_root: parent.body.repository_root.clone(),
            generation: parent.body.generation + 1,
            previous: Some(parent.id.clone()),
            epoch,
            admin_threshold: 1,
            devices,
            epoch_wraps: Vec::new(),
        };
        let (state, _, bytes) = Self::create(body, epoch_key, signer)?;
        Ok((state, bytes))
    }

    fn create(
        mut body: PolicyBody,
        epoch_key: &[u8; 32],
        signer: &KeyFile,
    ) -> Result<(Self, [u8; 32], Vec<u8>)> {
        validate_devices(&body.devices)?;
        validate_device_roots(&body)?;
        let aad = epoch_aad(&body.repository_root, body.generation, body.epoch);
        let mut wraps = Vec::new();
        for device in body
            .devices
            .iter()
            .filter(|device| device.active() && device.roles.reader)
        {
            let (encapsulated, ciphertext) =
                wrap_epoch_key(&device.public.wrapping_public_key, epoch_key, &aad)?;
            wraps.push(EpochWrap {
                device_id: device.public.device_id.clone(),
                encapsulated_key: BASE64.encode(encapsulated),
                ciphertext: BASE64.encode(ciphertext),
            });
        }
        wraps.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        body.epoch_wraps = wraps;
        let exact_body = serde_json::to_vec(&body)?;
        let signature = PolicySignature {
            device_id: signer.device_id()?,
            signature: BASE64.encode(signer.sign_domain(POLICY_SIGNATURE_DOMAIN, &exact_body)?),
        };
        let object = PolicyObject {
            body: BASE64.encode(&exact_body),
            signatures: vec![signature.clone()],
        };
        let bytes = serde_json::to_vec(&object)?;
        let state = Self {
            id: object_id(&bytes),
            body,
            exact_body,
            signatures: vec![signature],
        };
        Ok((state, *epoch_key, bytes))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let object: PolicyObject = serde_json::from_slice(bytes).context("parse policy object")?;
        let exact_body = BASE64.decode(object.body).context("decode policy body")?;
        let body: PolicyBody = serde_json::from_slice(&exact_body).context("parse policy body")?;
        if body.format_version != POLICY_FORMAT_VERSION {
            bail!("unsupported policy format {}", body.format_version)
        }
        validate_devices(&body.devices)?;
        validate_device_roots(&body)?;
        validate_wraps(&body)?;
        Ok(Self {
            id: object_id(bytes),
            body,
            exact_body,
            signatures: object.signatures,
        })
    }

    pub fn validate_genesis(&self, expected_root: &str) -> Result<()> {
        if self.body.generation != 0 || self.body.previous.is_some() {
            bail!("invalid genesis policy position")
        }
        if self.body.repository_root != expected_root {
            bail!("policy repository root does not match key file")
        }
        if self.body.devices.len() != 1
            || self.body.devices[0].roles != DeviceRoles::owner()
            || !self.body.devices[0].active()
            || repository_root_for_device(&self.body.devices[0].public)? != expected_root
        {
            bail!("genesis policy is not bound to the repository owner key")
        }
        if self.body.admin_threshold != 1 {
            bail!("only single-admin policy threshold 1 is supported")
        }
        self.verify_against_admins(&self.body.devices)
    }

    pub fn validate_successor(&self, parent: &PolicyState) -> Result<()> {
        if self.body.repository_root != parent.body.repository_root {
            bail!("policy repository root changed")
        }
        if self.body.generation != parent.body.generation + 1 {
            bail!("policy generation is not consecutive")
        }
        if self.body.previous.as_deref() != Some(parent.id.as_str()) {
            bail!("policy previous pointer does not match")
        }
        if parent.body.admin_threshold != 1 || self.body.admin_threshold != 1 {
            bail!("only single-admin policy threshold 1 is supported")
        }
        self.verify_against_admins(&parent.body.devices)?;
        for old in &parent.body.devices {
            let new = self
                .body
                .devices
                .iter()
                .find(|device| device.public.device_id == old.public.device_id)
                .context("policy removed a historical device record")?;
            if new.public != old.public {
                bail!("policy changed a device's public identity")
            }
            if old.revoked_at.is_some() && new.revoked_at != old.revoked_at {
                bail!("policy changed or reactivated a revoked device")
            }
            if old.revoked_at.is_none()
                && new.revoked_at.is_some()
                && new.revoked_at != Some(self.body.generation)
            {
                bail!("device revocation generation is invalid")
            }
        }
        for device in &self.body.devices {
            let was_already_revoked = parent
                .device(&device.public.device_id)
                .is_some_and(|old| old.revoked_at == device.revoked_at && old.revoked_at.is_some());
            if device.revoked_at.is_some()
                && !was_already_revoked
                && device.revoked_at != Some(self.body.generation)
            {
                bail!("device revocation generation is invalid")
            }
        }
        if !self
            .body
            .devices
            .iter()
            .any(|d| d.active() && d.roles.administrator)
        {
            bail!("policy must retain at least one active administrator")
        }
        let removed_reader = parent.body.devices.iter().any(|old| {
            old.active()
                && old.roles.reader
                && !self.body.devices.iter().any(|new| {
                    new.public.device_id == old.public.device_id && new.active() && new.roles.reader
                })
        });
        if removed_reader && self.body.epoch <= parent.body.epoch {
            bail!("reader removal requires an epoch rotation")
        }
        if self.body.epoch < parent.body.epoch || self.body.epoch > parent.body.epoch + 1 {
            bail!("policy epoch must stay unchanged or advance by one")
        }
        Ok(())
    }

    fn verify_against_admins(&self, devices: &[DeviceRecord]) -> Result<()> {
        if self.signatures.len() != 1 {
            bail!("single-admin policies require exactly one signature")
        }
        let signature = &self.signatures[0];
        let signer = devices
            .iter()
            .find(|device| {
                device.public.device_id == signature.device_id
                    && device.active()
                    && device.roles.administrator
            })
            .context("policy was not signed by an active parent administrator")?;
        let bytes = BASE64.decode(&signature.signature)?;
        verify_domain(
            &signer.public.signing_public_key,
            POLICY_SIGNATURE_DOMAIN,
            &self.exact_body,
            &bytes,
        )
    }

    pub fn unwrap_epoch(&self, key: &KeyFile) -> Result<[u8; 32]> {
        if key.repository_root != self.body.repository_root {
            bail!("key file belongs to a different repository")
        }
        let device_id = key.device_id()?;
        let wrap = self
            .body
            .epoch_wraps
            .iter()
            .find(|wrap| wrap.device_id == device_id)
            .context("device is not an active reader in the current policy")?;
        key.unwrap_epoch_key(
            &BASE64.decode(&wrap.encapsulated_key)?,
            &BASE64.decode(&wrap.ciphertext)?,
            &epoch_aad(
                &self.body.repository_root,
                self.body.generation,
                self.body.epoch,
            ),
        )
    }

    pub fn device(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.body
            .devices
            .iter()
            .find(|device| device.public.device_id == device_id)
    }

    pub fn is_active_writer(&self, device_id: &str) -> bool {
        self.device(device_id)
            .is_some_and(|device| device.active() && device.roles.writer)
    }

    pub fn is_active_admin(&self, device_id: &str) -> bool {
        self.device(device_id)
            .is_some_and(|device| device.active() && device.roles.administrator)
    }
}

fn validate_devices(devices: &[DeviceRecord]) -> Result<()> {
    let mut ids = HashSet::new();
    for device in devices {
        validate_public_device(&device.public)?;
        if !ids.insert(&device.public.device_id) {
            bail!("policy contains a duplicate device id")
        }
        if device.roles.writer && !device.roles.reader {
            bail!("writer devices must also be readers")
        }
        if device.roles.administrator && !device.roles.reader {
            bail!("administrator devices must also be readers")
        }
    }
    Ok(())
}

fn validate_wraps(body: &PolicyBody) -> Result<()> {
    let active_readers: HashSet<_> = body
        .devices
        .iter()
        .filter(|device| device.active() && device.roles.reader)
        .map(|device| device.public.device_id.as_str())
        .collect();
    let wrapped: HashSet<_> = body
        .epoch_wraps
        .iter()
        .map(|wrap| wrap.device_id.as_str())
        .collect();
    if wrapped.len() != body.epoch_wraps.len() || wrapped != active_readers {
        bail!("policy epoch wraps must match the active reader set exactly")
    }
    Ok(())
}

fn validate_device_roots(body: &PolicyBody) -> Result<()> {
    if body
        .devices
        .iter()
        .any(|device| device.public.repository_root != body.repository_root)
    {
        bail!("device public key belongs to a different repository")
    }
    Ok(())
}

fn epoch_aad(root: &str, generation: u64, epoch: u64) -> Vec<u8> {
    format!("git-remote-e2ee epoch v2\0{root}\0{generation}\0{epoch}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_self_signed_and_epoch_is_recipient_wrapped() {
        let key = KeyFile::generate();
        let (policy, epoch, bytes) = PolicyState::genesis(&key).unwrap();
        let parsed = PolicyState::parse(&bytes).unwrap();
        parsed.validate_genesis(&key.repository_root).unwrap();
        assert_eq!(parsed.unwrap_epoch(&key).unwrap(), epoch);
        assert_eq!(parsed.id, policy.id);
    }

    #[test]
    fn successor_is_authorized_by_parent_admin() {
        let admin = KeyFile::generate();
        let outsider = KeyFile::generate_for_repository(admin.repository_root.clone()).unwrap();
        let (parent, epoch, _) = PolicyState::genesis(&admin).unwrap();
        let (policy, bytes) =
            PolicyState::successor(&parent, parent.body.devices.clone(), 0, &epoch, &outsider)
                .unwrap();
        let parsed = PolicyState::parse(&bytes).unwrap();
        assert_eq!(parsed.id, policy.id);
        assert!(parsed.validate_successor(&parent).is_err());
    }

    #[test]
    fn genesis_cannot_be_substituted_under_a_known_repository_root() {
        let owner = KeyFile::generate();
        let attacker = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (_, _, forged_bytes) = PolicyState::genesis(&attacker).unwrap();
        let forged = PolicyState::parse(&forged_bytes).unwrap();
        assert!(forged.validate_genesis(&owner.repository_root).is_err());
    }

    #[test]
    fn successor_rejects_incorrect_revocation_generation() {
        let owner = KeyFile::generate();
        let second = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (parent, epoch, _) = PolicyState::genesis(&owner).unwrap();
        let mut devices = parent.body.devices.clone();
        devices.push(DeviceRecord {
            public: second.public_device().unwrap(),
            roles: DeviceRoles::collaborator(),
            revoked_at: Some(parent.body.generation),
        });
        let body = PolicyBody {
            format_version: POLICY_FORMAT_VERSION,
            repository_root: parent.body.repository_root.clone(),
            generation: parent.body.generation + 1,
            previous: Some(parent.id.clone()),
            epoch: parent.body.epoch,
            admin_threshold: 1,
            devices,
            epoch_wraps: Vec::new(),
        };
        let (malformed, _, _) = PolicyState::create(body, &epoch, &owner).unwrap();
        assert!(malformed.validate_successor(&parent).is_err());
    }
}
