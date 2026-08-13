use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::{KeyFile, PublicDevice, object_id, open_with_key, random_key, seal_with_key};
use crate::git;
use crate::manifest::{
    Manifest, ManifestAuthorization, ManifestHeader, PackDescriptor, open_manifest, pack_aad,
    peek_manifest_header, read_manifest_header, seal_manifest, unwrap_pack_key, wrap_pack_key,
};
use crate::policy::{DeviceRecord, DeviceRoles, PolicyState};
use crate::storage::{ObjectKind, Storage};

#[derive(Debug, Default, Serialize, Deserialize)]
struct ClientState {
    #[serde(default)]
    packs: Vec<String>,
    head_id: Option<String>,
    generation: Option<u64>,
    #[serde(default)]
    policy_generation: Option<u64>,
    #[serde(default)]
    repository_root: Option<String>,
}

pub struct EncryptedRepository<S> {
    storage: S,
    key: KeyFile,
}

impl<S: Storage> EncryptedRepository<S> {
    pub fn new(storage: S, key: KeyFile) -> Self {
        Self { storage, key }
    }

    pub fn initialize(&self) -> Result<String> {
        if self.storage.read_head()?.is_some() {
            bail!("encrypted repository is already initialized")
        }
        let (policy, epoch_key, policy_bytes) = PolicyState::genesis(&self.key)?;
        self.storage
            .put_object_if_absent(ObjectKind::Policy, &policy.id, &policy_bytes)?;
        let genesis = Manifest::genesis(self.key.repository_root.clone(), &policy);
        self.commit_manifest(
            None,
            &policy,
            None,
            &epoch_key,
            ManifestAuthorization::PolicyTransition,
            genesis,
        )
    }

    pub fn add_device(
        &self,
        public: PublicDevice,
        roles: DeviceRoles,
        pin_path: &Path,
    ) -> Result<(String, String)> {
        let (head_id, current, policy, _) = self.current_state()?;
        self.validate_pinned_head(&head_id, &current, &read_client_state(pin_path)?)?;
        self.require_admin(&policy)?;
        if policy.device(&public.device_id).is_some() {
            bail!("device already exists in policy")
        }
        let epoch_key = policy.unwrap_epoch(&self.key)?;
        let mut devices = policy.body.devices.clone();
        devices.push(DeviceRecord {
            public,
            roles,
            revoked_at: None,
        });
        let (next_policy, policy_bytes) =
            PolicyState::successor(&policy, devices, policy.body.epoch, &epoch_key, &self.key)?;
        let next = transition_manifest(&head_id, &current, &next_policy, current.packs.clone());
        let result = self.publish_policy_transition(
            &head_id,
            &policy,
            &next_policy,
            &policy_bytes,
            &epoch_key,
            next.clone(),
        )?;
        write_client_state(pin_path, &HashSet::new(), &result.0, &next)?;
        Ok(result)
    }

    pub fn revoke_device(&self, device_id: &str, pin_path: &Path) -> Result<(String, String)> {
        let (head_id, current, policy, old_epoch_key) = self.current_state()?;
        self.validate_pinned_head(&head_id, &current, &read_client_state(pin_path)?)?;
        self.require_admin(&policy)?;
        let mut devices = policy.body.devices.clone();
        let target = devices
            .iter_mut()
            .find(|device| device.public.device_id == device_id && device.active())
            .context("device is not active in the current policy")?;
        target.revoked_at = Some(policy.body.generation + 1);
        if !devices
            .iter()
            .any(|device| device.active() && device.roles.reader)
        {
            bail!("cannot revoke the last active reader")
        }
        if !devices
            .iter()
            .any(|device| device.active() && device.roles.administrator)
        {
            bail!("cannot revoke the last active administrator")
        }
        let new_epoch_key = random_key();
        let new_epoch = policy.body.epoch + 1;
        let packs = current
            .packs
            .iter()
            .map(|pack| {
                let pack_key = unwrap_pack_key(
                    &old_epoch_key,
                    &current.repository_root,
                    current.epoch,
                    pack,
                )?;
                Ok(PackDescriptor {
                    id: pack.id.clone(),
                    plaintext_size: pack.plaintext_size,
                    wrapped_key: wrap_pack_key(
                        &new_epoch_key,
                        &current.repository_root,
                        new_epoch,
                        &pack.id,
                        &pack_key,
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let (next_policy, policy_bytes) =
            PolicyState::successor(&policy, devices, new_epoch, &new_epoch_key, &self.key)?;
        let next = transition_manifest(&head_id, &current, &next_policy, packs);
        let result = self.publish_policy_transition(
            &head_id,
            &policy,
            &next_policy,
            &policy_bytes,
            &new_epoch_key,
            next.clone(),
        )?;
        write_client_state(pin_path, &HashSet::new(), &result.0, &next)?;
        Ok(result)
    }

    pub fn pin_admin_state(&self, pin_path: &Path) -> Result<()> {
        let (head_id, manifest, _, _) = self.current_state()?;
        let previous = read_client_state(pin_path)?;
        self.validate_pinned_head(&head_id, &manifest, &previous)?;
        write_client_state(pin_path, &HashSet::new(), &head_id, &manifest)
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        Ok(self.current_state()?.2.body.devices)
    }

    fn publish_policy_transition(
        &self,
        head_id: &str,
        parent: &PolicyState,
        policy: &PolicyState,
        policy_bytes: &[u8],
        epoch_key: &[u8; 32],
        manifest: Manifest,
    ) -> Result<(String, String)> {
        self.storage
            .put_object_if_absent(ObjectKind::Policy, &policy.id, policy_bytes)?;
        let manifest_id = self.commit_manifest(
            Some(head_id),
            policy,
            Some(parent),
            epoch_key,
            ManifestAuthorization::PolicyTransition,
            manifest,
        )?;
        Ok((manifest_id, policy.id.clone()))
    }

    fn require_admin(&self, policy: &PolicyState) -> Result<()> {
        if !policy.is_active_admin(&self.key.device_id()?) {
            bail!("device is not an active administrator")
        }
        Ok(())
    }

    pub fn push_ref(&self, repo: &Path, reference: &str, force: bool) -> Result<String> {
        self.push_update(repo, reference, reference, force)
    }

    pub fn push_update(
        &self,
        repo: &Path,
        source_ref: &str,
        destination_ref: &str,
        force: bool,
    ) -> Result<String> {
        self.push_update_inner(repo, None, source_ref, destination_ref, force)
    }

    pub fn push_update_for_remote(
        &self,
        repo: &Path,
        remote_name: &str,
        source_ref: &str,
        destination_ref: &str,
        force: bool,
    ) -> Result<String> {
        self.push_update_inner(repo, Some(remote_name), source_ref, destination_ref, force)
    }

    fn push_update_inner(
        &self,
        repo: &Path,
        remote_name: Option<&str>,
        source_ref: &str,
        destination_ref: &str,
        force: bool,
    ) -> Result<String> {
        let (head_id, current, policy, epoch_key, next_object, non_fast_forward) =
            self.preflight_push(repo, remote_name, source_ref, destination_ref, force)?;
        if current.refs.get(destination_ref) == Some(&next_object) {
            return Ok(head_id);
        }
        let mut next_refs = current.refs.clone();
        next_refs.insert(destination_ref.to_owned(), next_object.clone());
        let mut exclusions = BTreeMap::new();
        if !non_fast_forward {
            for (reference, object) in &current.refs {
                if git::object_exists(repo, object)? {
                    exclusions.insert(reference.clone(), object.clone());
                }
            }
        }
        let pack_refs = BTreeMap::from([(destination_ref.to_owned(), next_object)]);
        let pack = git::create_incremental_pack(repo, &pack_refs, &exclusions)?;
        let pack_key = random_key();
        let encrypted_pack = seal_with_key(&pack_key, &pack, &pack_aad(&current.repository_root))?;
        let pack_id = object_id(&encrypted_pack);
        self.storage
            .put_object_if_absent(ObjectKind::Pack, &pack_id, &encrypted_pack)?;
        let mut packs = current.packs.clone();
        packs.push(PackDescriptor {
            id: pack_id.clone(),
            plaintext_size: pack.len() as u64,
            wrapped_key: wrap_pack_key(
                &epoch_key,
                &current.repository_root,
                current.epoch,
                &pack_id,
                &pack_key,
            )?,
        });
        let next = Manifest {
            format_version: current.format_version,
            repository_root: current.repository_root.clone(),
            generation: current.generation + 1,
            previous: Some(head_id.clone()),
            policy_id: policy.id.clone(),
            policy_generation: policy.body.generation,
            epoch: policy.body.epoch,
            authorization: ManifestAuthorization::Writer,
            refs: next_refs,
            packs,
        };
        let next_id = self.commit_manifest(
            Some(&head_id),
            &policy,
            None,
            &epoch_key,
            ManifestAuthorization::Writer,
            next.clone(),
        )?;
        if let Some(remote_name) = remote_name {
            self.pin_manifest(repo, remote_name, &next_id, &next)?;
        }
        Ok(next_id)
    }

    pub fn validate_push_update(
        &self,
        repo: &Path,
        source_ref: &str,
        destination_ref: &str,
        force: bool,
    ) -> Result<()> {
        self.preflight_push(repo, None, source_ref, destination_ref, force)?;
        Ok(())
    }

    pub fn validate_push_update_for_remote(
        &self,
        repo: &Path,
        remote_name: &str,
        source_ref: &str,
        destination_ref: &str,
        force: bool,
    ) -> Result<()> {
        self.preflight_push(repo, Some(remote_name), source_ref, destination_ref, force)?;
        Ok(())
    }

    fn preflight_push(
        &self,
        repo: &Path,
        remote_name: Option<&str>,
        source_ref: &str,
        destination_ref: &str,
        force: bool,
    ) -> Result<(String, Manifest, PolicyState, [u8; 32], String, bool)> {
        if !destination_ref.starts_with("refs/heads/") {
            bail!("only refs/heads/* destinations are supported")
        }
        git::ensure_repository(repo)?;
        let (head_id, current, policy, epoch_key) = self.current_state()?;
        if !policy.is_active_writer(&self.key.device_id()?) {
            bail!("device is not an active writer")
        }
        if let Some(remote_name) = remote_name {
            self.validate_and_pin_manifest(repo, remote_name, &head_id, &current)?;
        }
        let next_object = git::resolve_ref(repo, source_ref)?;
        if current.refs.get(destination_ref) == Some(&next_object) {
            return Ok((head_id, current, policy, epoch_key, next_object, false));
        }
        let non_fast_forward = if let Some(old_object) = current.refs.get(destination_ref) {
            if !git::object_exists(repo, old_object)? {
                bail!("remote tip for {destination_ref} is missing locally; fetch first")
            }
            !git::is_ancestor(repo, old_object, &next_object)?
        } else {
            false
        };
        if non_fast_forward && !force {
            bail!("non-fast-forward update rejected for {destination_ref}")
        }
        Ok((
            head_id,
            current,
            policy,
            epoch_key,
            next_object,
            non_fast_forward,
        ))
    }

    pub fn fetch_into(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        let manifest = self.import_packs(repo, remote_name)?;
        for (reference, object) in &manifest.refs {
            let short = reference
                .strip_prefix("refs/heads/")
                .with_context(|| format!("unsupported remote ref {reference}"))?;
            git::update_ref(repo, &format!("refs/remotes/{remote_name}/{short}"), object)?;
        }
        Ok(manifest)
    }

    pub fn observe_manifest(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let (head_id, manifest, _, _) = self.current_state()?;
        self.validate_and_pin_manifest(repo, remote_name, &head_id, &manifest)?;
        Ok(manifest)
    }

    pub fn import_packs(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let (head_id, manifest, _, epoch_key) = self.current_state()?;
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(&head_id, &manifest, &state)?;
        let mut imported: HashSet<String> = state.packs.into_iter().collect();
        for descriptor in &manifest.packs {
            if imported.contains(&descriptor.id) {
                continue;
            }
            let encrypted = self.storage.get_object(ObjectKind::Pack, &descriptor.id)?;
            if object_id(&encrypted) != descriptor.id {
                bail!("pack ciphertext hash mismatch for {}", descriptor.id)
            }
            let pack_key = unwrap_pack_key(
                &epoch_key,
                &manifest.repository_root,
                manifest.epoch,
                descriptor,
            )?;
            let pack = open_with_key(&pack_key, &encrypted, &pack_aad(&manifest.repository_root))?;
            if pack.len() as u64 != descriptor.plaintext_size {
                bail!("pack plaintext size mismatch for {}", descriptor.id)
            }
            git::import_pack(repo, &pack)?;
            imported.insert(descriptor.id.clone());
        }
        write_client_state(&state_path, &imported, &head_id, &manifest)?;
        Ok(manifest)
    }

    fn validate_and_pin_manifest(
        &self,
        repo: &Path,
        remote_name: &str,
        head_id: &str,
        manifest: &Manifest,
    ) -> Result<()> {
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(head_id, manifest, &state)?;
        write_client_state(
            &state_path,
            &state.packs.into_iter().collect(),
            head_id,
            manifest,
        )
    }

    fn pin_manifest(
        &self,
        repo: &Path,
        remote_name: &str,
        head_id: &str,
        manifest: &Manifest,
    ) -> Result<()> {
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        write_client_state(
            &state_path,
            &state.packs.into_iter().collect(),
            head_id,
            manifest,
        )
    }

    fn validate_pinned_head(
        &self,
        current_id: &str,
        current: &Manifest,
        state: &ClientState,
    ) -> Result<()> {
        if let Some(root) = &state.repository_root
            && root != &current.repository_root
        {
            bail!("remote repository root changed")
        }
        if let Some(policy_generation) = state.policy_generation
            && current.policy_generation < policy_generation
        {
            bail!("remote policy rolled back")
        }
        let (Some(pinned_id), Some(pinned_generation)) =
            (state.head_id.as_deref(), state.generation)
        else {
            return Ok(());
        };
        if current.generation < pinned_generation {
            bail!(
                "remote manifest rolled back from generation {pinned_generation} to {}",
                current.generation
            )
        }
        let mut id = current_id.to_owned();
        let mut manifest = current.clone();
        while manifest.generation > pinned_generation {
            let previous_id = manifest
                .previous
                .clone()
                .context("remote manifest chain ended before pinned generation")?;
            let previous = self.read_manifest(&previous_id)?;
            manifest.validate_successor(&previous_id, &previous)?;
            id = previous_id;
            manifest = previous;
        }
        if id != pinned_id {
            bail!("remote manifest history forked from the locally pinned head")
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<Manifest> {
        let (mut id, manifest, _, epoch_key) = self.current_state()?;
        let newest = manifest.clone();
        for pack in &manifest.packs {
            let encrypted = self.storage.get_object(ObjectKind::Pack, &pack.id)?;
            if object_id(&encrypted) != pack.id {
                bail!("pack ciphertext hash mismatch for {}", pack.id)
            }
            let pack_key =
                unwrap_pack_key(&epoch_key, &manifest.repository_root, manifest.epoch, pack)?;
            open_with_key(&pack_key, &encrypted, &pack_aad(&manifest.repository_root))?;
        }

        let mut seen = HashSet::new();
        let mut header = self.read_verified_header(&id)?;
        loop {
            if !seen.insert(id.clone()) {
                bail!("manifest chain contains a cycle")
            }
            let Some(previous_id) = header.previous.clone() else {
                if header.generation != 0 {
                    bail!("manifest chain terminated above generation zero")
                }
                break;
            };
            let previous = self.read_verified_header(&previous_id)?;
            if header.repository_root != previous.repository_root
                || header.generation != previous.generation + 1
                || header.policy_generation < previous.policy_generation
            {
                bail!("invalid manifest header chain")
            }
            id = previous_id;
            header = previous;
        }
        Ok(newest)
    }

    fn read_verified_header(&self, id: &str) -> Result<ManifestHeader> {
        let bytes = self.storage.get_object(ObjectKind::Manifest, id)?;
        if object_id(&bytes) != id {
            bail!("manifest ciphertext hash mismatch")
        }
        let unverified = peek_manifest_header(&bytes)?;
        let policy = self.read_policy(&unverified.policy_id)?;
        let parent = match &policy.body.previous {
            Some(parent_id) => Some(self.read_policy(parent_id)?),
            None => None,
        };
        read_manifest_header(&bytes, &policy, parent.as_ref())
    }

    pub fn current_manifest(&self) -> Result<(String, Manifest)> {
        let (id, manifest, _, _) = self.current_state()?;
        Ok((id, manifest))
    }

    fn current_state(&self) -> Result<(String, Manifest, PolicyState, [u8; 32])> {
        let head = self
            .storage
            .read_head()?
            .context("encrypted repository is not initialized")?;
        self.state_at(&head)
    }

    fn state_at(&self, id: &str) -> Result<(String, Manifest, PolicyState, [u8; 32])> {
        let encrypted = self.storage.get_object(ObjectKind::Manifest, id)?;
        if object_id(&encrypted) != id {
            bail!("manifest ciphertext hash mismatch")
        }
        let header = peek_manifest_header(&encrypted)?;
        let policy = self.read_policy(&header.policy_id)?;
        let parent = match &policy.body.previous {
            Some(id) => Some(self.read_policy(id)?),
            None => None,
        };
        let epoch_key = policy.unwrap_epoch(&self.key)?;
        let manifest = open_manifest(&encrypted, &policy, parent.as_ref(), &epoch_key)?;
        Ok((id.to_owned(), manifest, policy, epoch_key))
    }

    fn read_manifest(&self, id: &str) -> Result<Manifest> {
        Ok(self.state_at(id)?.1)
    }

    fn read_policy(&self, id: &str) -> Result<PolicyState> {
        let bytes = self.storage.get_object(ObjectKind::Policy, id)?;
        if object_id(&bytes) != id {
            bail!("policy object hash mismatch")
        }
        let policy = PolicyState::parse(&bytes)?;
        if policy.id != id {
            bail!("policy id mismatch")
        }
        match &policy.body.previous {
            Some(previous_id) => {
                let parent = self.read_policy(previous_id)?;
                policy.validate_successor(&parent)?;
            }
            None => policy.validate_genesis(&self.key.repository_root)?,
        }
        Ok(policy)
    }

    fn commit_manifest(
        &self,
        expected: Option<&str>,
        policy: &PolicyState,
        parent_policy: Option<&PolicyState>,
        epoch_key: &[u8; 32],
        authorization: ManifestAuthorization,
        manifest: Manifest,
    ) -> Result<String> {
        if let Some(previous_id) = expected {
            let previous = self.read_manifest(previous_id)?;
            manifest.validate_successor(previous_id, &previous)?;
        }
        let encrypted = seal_manifest(&self.key, policy, epoch_key, authorization, manifest)?;
        let id = object_id(&encrypted);
        self.storage
            .put_object_if_absent(ObjectKind::Manifest, &id, &encrypted)?;
        // Reading our own object catches policy/signature/envelope mistakes before publication.
        open_manifest(&encrypted, policy, parent_policy, epoch_key)?;
        self.storage.compare_and_swap_head(expected, &id)?;
        Ok(id)
    }
}

fn transition_manifest(
    head_id: &str,
    current: &Manifest,
    policy: &PolicyState,
    packs: Vec<PackDescriptor>,
) -> Manifest {
    Manifest {
        format_version: current.format_version,
        repository_root: current.repository_root.clone(),
        generation: current.generation + 1,
        previous: Some(head_id.to_owned()),
        policy_id: policy.id.clone(),
        policy_generation: policy.body.generation,
        epoch: policy.body.epoch,
        authorization: ManifestAuthorization::PolicyTransition,
        refs: current.refs.clone(),
        packs,
    }
}

fn git_state_directory(repo: &Path) -> Result<std::path::PathBuf> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--absolute-git-dir"])
        .output()?;
    if !output.status.success() {
        bail!("could not locate Git directory")
    }
    Ok(String::from_utf8(output.stdout)?.trim().into())
}

fn client_state_path(repo: &Path, remote_name: &str) -> Result<std::path::PathBuf> {
    validate_remote_name(remote_name)?;
    let directory = git_state_directory(repo)?
        .join("git-remote-e2ee")
        .join(remote_name);
    fs::create_dir_all(&directory)?;
    Ok(directory.join("state.json"))
}

fn read_client_state(path: &Path) -> Result<ClientState> {
    match fs::read(path) {
        Ok(contents) => {
            serde_json::from_slice(&contents).context("parse git-remote-e2ee client state")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ClientState::default()),
        Err(error) => Err(error.into()),
    }
}

fn write_client_state(
    path: &Path,
    values: &HashSet<String>,
    head_id: &str,
    manifest: &Manifest,
) -> Result<()> {
    let mut values: Vec<_> = values.iter().cloned().collect();
    values.sort();
    let state = ClientState {
        packs: values,
        head_id: Some(head_id.to_owned()),
        generation: Some(manifest.generation),
        policy_generation: Some(manifest.policy_generation),
        repository_root: Some(manifest.repository_root.clone()),
    };
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = path.with_extension(format!("json.{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(&state)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(path.parent().context("client state path has no parent")?)?.sync_all()?;
    Ok(())
}

fn validate_remote_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("remote name may contain only ASCII letters, digits, '-' and '_'")
    }
    Ok(())
}
