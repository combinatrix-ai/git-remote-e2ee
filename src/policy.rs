use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    KeyFile, PublicDevice, object_id, repository_root_for_device, validate_public_device,
    verify_domain,
};

pub const POLICY_FORMAT_VERSION: u32 = 6;
const POLICY_SIGNATURE_DOMAIN: &[u8] = b"git-remote-e2ee policy v6\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRoles {
    pub reader: bool,
    pub writer: bool,
    pub administrator: bool,
}

impl DeviceRoles {
    pub fn reader() -> Self {
        Self {
            reader: true,
            writer: false,
            administrator: false,
        }
    }

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
    pub label: String,
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
pub struct PolicyBody {
    pub format_version: u32,
    pub repository_root: String,
    pub generation: u64,
    pub previous: Option<String>,
    pub admin_threshold: u32,
    pub devices: Vec<DeviceRecord>,
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
    pub fn genesis(key: &KeyFile, owner_label: &str) -> Result<(Self, Vec<u8>)> {
        let public = key.public_device()?;
        let body = PolicyBody {
            format_version: POLICY_FORMAT_VERSION,
            repository_root: key.repository_root.clone(),
            generation: 0,
            previous: None,
            admin_threshold: 1,
            devices: vec![DeviceRecord {
                public,
                label: owner_label.to_owned(),
                roles: DeviceRoles::owner(),
                revoked_at: None,
            }],
        };
        Self::create(body, key)
    }

    pub fn successor(
        parent: &PolicyState,
        mut devices: Vec<DeviceRecord>,
        signer: &KeyFile,
    ) -> Result<(Self, Vec<u8>)> {
        devices.sort_by(|a, b| a.public.device_id.cmp(&b.public.device_id));
        let body = PolicyBody {
            format_version: POLICY_FORMAT_VERSION,
            repository_root: parent.body.repository_root.clone(),
            generation: parent.body.generation + 1,
            previous: Some(parent.id.clone()),
            admin_threshold: 1,
            devices,
        };
        Self::create(body, signer)
    }

    fn create(body: PolicyBody, signer: &KeyFile) -> Result<(Self, Vec<u8>)> {
        validate_devices(&body.devices)?;
        validate_device_roots(&body)?;
        validate_active_roles(&body)?;
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
        Ok((state, bytes))
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
        validate_active_roles(&body)?;
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
            if new.label != old.label {
                bail!("policy changed a device's label")
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
        validate_active_roles(&self.body)
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
        verify_domain(
            &signer.public.signing_public_key,
            POLICY_SIGNATURE_DOMAIN,
            &self.exact_body,
            &BASE64.decode(&signature.signature)?,
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

    pub fn is_active_reader(&self, device_id: &str) -> bool {
        self.device(device_id)
            .is_some_and(|device| device.active() && device.roles.reader)
    }

    pub fn is_active_admin(&self, device_id: &str) -> bool {
        self.device(device_id)
            .is_some_and(|device| device.active() && device.roles.administrator)
    }
}

pub const MAX_DEVICE_LABEL_BYTES: usize = 64;

/// Labels are an administrator's claim for humans reading `device-list`; they
/// never select or authorize anything. Rejecting invisible and bidirectional
/// formatting characters keeps two labels from rendering identically.
pub fn validate_device_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > MAX_DEVICE_LABEL_BYTES {
        bail!("device label must be 1 to {MAX_DEVICE_LABEL_BYTES} bytes")
    }
    if label.trim() != label {
        bail!("device label must not start or end with whitespace")
    }
    if let Some(character) = label.chars().find(|&c| is_control_or_invisible(c)) {
        bail!(
            "device label contains control or invisible character U+{:04X}",
            u32::from(character)
        )
    }
    Ok(())
}

fn is_control_or_invisible(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
        )
}

fn validate_devices(devices: &[DeviceRecord]) -> Result<()> {
    let mut ids = HashSet::new();
    let mut active_labels = HashSet::new();
    for device in devices {
        validate_public_device(&device.public)?;
        if !ids.insert(&device.public.device_id) {
            bail!("policy contains a duplicate device id")
        }
        validate_device_label(&device.label)?;
        if device.active() && !active_labels.insert(device.label.as_str()) {
            bail!(
                "device label {:?} is already used by an active device",
                device.label
            )
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

fn validate_active_roles(body: &PolicyBody) -> Result<()> {
    if !body
        .devices
        .iter()
        .any(|device| device.active() && device.roles.reader)
    {
        bail!("policy must retain at least one active reader")
    }
    if !body
        .devices
        .iter()
        .any(|device| device.active() && device.roles.administrator)
    {
        bail!("policy must retain at least one active administrator")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_self_signed_and_contains_no_content_key() {
        let key = KeyFile::generate();
        let (policy, bytes) = PolicyState::genesis(&key, "owner").unwrap();
        let parsed = PolicyState::parse(&bytes).unwrap();
        parsed.validate_genesis(&key.repository_root).unwrap();
        assert_eq!(parsed.id, policy.id);
        assert!(!String::from_utf8(bytes).unwrap().contains("epoch"));
    }

    #[test]
    fn successor_is_authorized_by_parent_admin() {
        let admin = KeyFile::generate();
        let outsider = KeyFile::generate_for_repository(admin.repository_root.clone()).unwrap();
        let (parent, _) = PolicyState::genesis(&admin, "owner").unwrap();
        let result = PolicyState::successor(&parent, parent.body.devices.clone(), &outsider);
        assert!(result.is_ok());
        let (unauthorized, _) = result.unwrap();
        assert!(unauthorized.validate_successor(&parent).is_err());
    }

    #[test]
    fn writers_and_administrators_must_also_be_readers() {
        let owner = KeyFile::generate();
        let (parent, _) = PolicyState::genesis(&owner, "owner").unwrap();
        for roles in [
            DeviceRoles {
                reader: false,
                writer: true,
                administrator: false,
            },
            DeviceRoles {
                reader: false,
                writer: false,
                administrator: true,
            },
        ] {
            let added = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
            let mut devices = parent.body.devices.clone();
            devices.push(DeviceRecord {
                public: added.public_device().unwrap(),
                label: added.device_id().unwrap(),
                roles,
                revoked_at: None,
            });
            assert!(PolicyState::successor(&parent, devices, &owner).is_err());
        }
    }

    #[test]
    fn genesis_cannot_be_substituted_under_a_known_repository_root() {
        let expected = KeyFile::generate();
        let attacker = KeyFile::generate();
        let (substitute, _) = PolicyState::genesis(&attacker, "owner").unwrap();
        assert!(
            substitute
                .validate_genesis(&expected.repository_root)
                .is_err()
        );
    }

    #[test]
    fn successor_rejects_incorrect_revocation_generation() {
        let owner = KeyFile::generate();
        let (parent, _) = PolicyState::genesis(&owner, "owner").unwrap();
        let collaborator = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let mut devices = parent.body.devices.clone();
        devices.push(DeviceRecord {
            public: collaborator.public_device().unwrap(),
            label: collaborator.device_id().unwrap(),
            roles: DeviceRoles::collaborator(),
            revoked_at: None,
        });
        let (with_collaborator, _) = PolicyState::successor(&parent, devices, &owner).unwrap();
        with_collaborator.validate_successor(&parent).unwrap();
        let mut malformed_devices = with_collaborator.body.devices.clone();
        malformed_devices
            .iter_mut()
            .find(|device| device.public.device_id == collaborator.device_id().unwrap())
            .unwrap()
            .revoked_at = Some(with_collaborator.body.generation + 2);
        let (malformed, _) =
            PolicyState::successor(&with_collaborator, malformed_devices, &owner).unwrap();
        assert!(malformed.validate_successor(&with_collaborator).is_err());
    }

    #[test]
    fn successor_cannot_reactivate_a_revoked_device() {
        let owner = KeyFile::generate();
        let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (genesis, _) = PolicyState::genesis(&owner, "owner").unwrap();
        let mut devices = genesis.body.devices.clone();
        devices.push(DeviceRecord {
            public: reader.public_device().unwrap(),
            label: reader.device_id().unwrap(),
            roles: DeviceRoles::collaborator(),
            revoked_at: None,
        });
        let (with_reader, _) = PolicyState::successor(&genesis, devices, &owner).unwrap();
        with_reader.validate_successor(&genesis).unwrap();

        let mut revoked_devices = with_reader.body.devices.clone();
        revoked_devices
            .iter_mut()
            .find(|device| device.public.device_id == reader.device_id().unwrap())
            .unwrap()
            .revoked_at = Some(with_reader.body.generation + 1);
        let (revoked, _) = PolicyState::successor(&with_reader, revoked_devices, &owner).unwrap();
        revoked.validate_successor(&with_reader).unwrap();

        let mut reactivated_devices = revoked.body.devices.clone();
        reactivated_devices
            .iter_mut()
            .find(|device| device.public.device_id == reader.device_id().unwrap())
            .unwrap()
            .revoked_at = None;
        let (reactivated, _) =
            PolicyState::successor(&revoked, reactivated_devices, &owner).unwrap();
        let error = reactivated
            .validate_successor(&revoked)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("changed or reactivated"),
            "unexpected error: {error}"
        );
    }

    /// Signs a body the way a malicious administrator's modified client would,
    /// skipping the checks `create` runs, and returns the bytes a receiver sees.
    fn sign_unchecked(body: &PolicyBody, signer: &KeyFile) -> Vec<u8> {
        let exact_body = serde_json::to_vec(body).unwrap();
        serde_json::to_vec(&PolicyObject {
            body: BASE64.encode(&exact_body),
            signatures: vec![PolicySignature {
                device_id: signer.device_id().unwrap(),
                signature: BASE64.encode(
                    signer
                        .sign_domain(POLICY_SIGNATURE_DOMAIN, &exact_body)
                        .unwrap(),
                ),
            }],
        })
        .unwrap()
    }

    #[test]
    fn received_genesis_with_an_invalid_owner_label_is_rejected() {
        let owner = KeyFile::generate();
        let (genesis, _) = PolicyState::genesis(&owner, "owner").unwrap();
        for label in [
            "",
            " owner",
            "own\u{202E}er",
            "a\u{200B}",
            "x\ny",
            &"a".repeat(65),
        ] {
            let mut body = genesis.body.clone();
            body.devices[0].label = label.to_owned();
            let received = PolicyState::parse(&sign_unchecked(&body, &owner))
                .and_then(|policy| policy.validate_genesis(&owner.repository_root));
            assert!(received.is_err(), "accepted owner label {label:?}");
        }
        assert!(PolicyState::genesis(&owner, "own\u{FEFF}er").is_err());
    }

    #[test]
    fn received_successor_with_a_duplicate_active_label_is_rejected() {
        let owner = KeyFile::generate();
        let (genesis, _) = PolicyState::genesis(&owner, "laptop").unwrap();
        let twin = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let mut body = genesis.body.clone();
        body.generation = 1;
        body.previous = Some(genesis.id.clone());
        body.devices.push(DeviceRecord {
            public: twin.public_device().unwrap(),
            label: "laptop".to_owned(),
            roles: DeviceRoles::collaborator(),
            revoked_at: None,
        });
        let received = PolicyState::parse(&sign_unchecked(&body, &owner))
            .and_then(|policy| policy.validate_successor(&genesis));
        let error = received.unwrap_err().to_string();
        assert!(error.contains("already used"), "unexpected error: {error}");
    }

    #[test]
    fn successor_cannot_relabel_an_existing_device() {
        let owner = KeyFile::generate();
        let (genesis, _) = PolicyState::genesis(&owner, "laptop").unwrap();
        let mut devices = genesis.body.devices.clone();
        devices[0].label = "renamed".to_owned();
        let (relabeled, bytes) = PolicyState::successor(&genesis, devices, &owner).unwrap();
        let received = PolicyState::parse(&bytes).unwrap();
        assert_eq!(received.id, relabeled.id);
        let error = received
            .validate_successor(&genesis)
            .unwrap_err()
            .to_string();
        assert!(error.contains("label"), "unexpected error: {error}");
    }

    #[test]
    fn a_revoked_label_is_free_for_a_new_device() {
        let owner = KeyFile::generate();
        let old = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let new = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let (genesis, _) = PolicyState::genesis(&owner, "laptop").unwrap();
        let mut devices = genesis.body.devices.clone();
        devices.push(DeviceRecord {
            public: old.public_device().unwrap(),
            label: "phone".to_owned(),
            roles: DeviceRoles::reader(),
            revoked_at: Some(1),
        });
        devices.push(DeviceRecord {
            public: new.public_device().unwrap(),
            label: "phone".to_owned(),
            roles: DeviceRoles::reader(),
            revoked_at: None,
        });
        let (_, bytes) = PolicyState::successor(&genesis, devices, &owner).unwrap();
        PolicyState::parse(&bytes)
            .unwrap()
            .validate_successor(&genesis)
            .unwrap();
    }
}
