use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    KeyFile, PublicDevice, SecretKey, SubkeyKind, derive_subkey, object_id, open_with_key,
    random_key, seal_with_key,
};
use crate::git;
use crate::manifest::{
    Manifest, ManifestAuthorization, ManifestHeader, PackDescriptor, open_manifest, pack_aad,
    peek_manifest_header, read_manifest_header, seal_manifest, unwrap_generation_key,
    unwrap_predecessor_key, wrap_predecessor_key,
};
use crate::policy::{DeviceRecord, DeviceRoles, PolicyState};
use crate::storage::{ObjectKind, Storage};

#[derive(Debug, Default, Serialize, Deserialize)]
struct ClientState {
    #[serde(default)]
    format_version: u64,
    #[serde(default)]
    packs: Vec<String>,
    head_id: Option<String>,
    generation: Option<u64>,
    #[serde(default)]
    imported_generation: Option<u64>,
    #[serde(default)]
    policy_generation: Option<u64>,
    #[serde(default)]
    repository_root: Option<String>,
}

#[derive(Clone)]
struct OpenedState {
    id: String,
    manifest: Manifest,
    header: ManifestHeader,
    policy: PolicyState,
    generation_key: SecretKey,
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
        let (policy, policy_bytes) = PolicyState::genesis(&self.key)?;
        self.storage
            .put_object_if_absent(ObjectKind::Policy, &policy.id, &policy_bytes)?;
        let generation_key = random_key();
        let genesis = Manifest::genesis(self.key.repository_root.clone(), &policy);
        self.commit_manifest(
            None,
            &policy,
            None,
            &generation_key,
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
        let current = self.current_state()?;
        self.validate_pinned_head(&current, &read_client_state(pin_path)?)?;
        self.require_admin(&current.policy)?;
        if current.policy.device(&public.device_id).is_some() {
            bail!("device already exists in policy")
        }
        let mut devices = current.policy.body.devices.clone();
        devices.push(DeviceRecord {
            public,
            roles,
            revoked_at: None,
        });
        let (next_policy, policy_bytes) =
            PolicyState::successor(&current.policy, devices, &self.key)?;
        let next_key = random_key();
        let next = transition_manifest(&current, &next_policy, &next_key)?;
        let result = self.publish_policy_transition(
            &current,
            &next_policy,
            &policy_bytes,
            &next_key,
            next.clone(),
        )?;
        write_client_state(pin_path, &HashSet::new(), &result.0, &next)?;
        Ok(result)
    }

    pub fn revoke_device(&self, device_id: &str, pin_path: &Path) -> Result<(String, String)> {
        let current = self.current_state()?;
        self.validate_pinned_head(&current, &read_client_state(pin_path)?)?;
        self.require_admin(&current.policy)?;
        let mut devices = current.policy.body.devices.clone();
        let target = devices
            .iter_mut()
            .find(|device| device.public.device_id == device_id && device.active())
            .context("device is not active in the current policy")?;
        target.revoked_at = Some(current.policy.body.generation + 1);
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
        let (next_policy, policy_bytes) =
            PolicyState::successor(&current.policy, devices, &self.key)?;
        let next_key = random_key();
        let next = transition_manifest(&current, &next_policy, &next_key)?;
        let result = self.publish_policy_transition(
            &current,
            &next_policy,
            &policy_bytes,
            &next_key,
            next.clone(),
        )?;
        write_client_state(pin_path, &HashSet::new(), &result.0, &next)?;
        Ok(result)
    }

    pub fn pin_admin_state(&self, pin_path: &Path) -> Result<()> {
        let current = self.current_state()?;
        let previous = read_client_state(pin_path)?;
        self.validate_pinned_head(&current, &previous)?;
        write_client_state(pin_path, &HashSet::new(), &current.id, &current.manifest)
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        Ok(self.current_state()?.policy.body.devices)
    }

    fn publish_policy_transition(
        &self,
        current: &OpenedState,
        policy: &PolicyState,
        policy_bytes: &[u8],
        generation_key: &[u8; 32],
        manifest: Manifest,
    ) -> Result<(String, String)> {
        self.storage
            .put_object_if_absent(ObjectKind::Policy, &policy.id, policy_bytes)?;
        let manifest_id = self.commit_manifest(
            Some(current),
            policy,
            Some(&current.policy),
            generation_key,
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
        let (current, next_object, non_fast_forward) =
            self.preflight_push(repo, remote_name, source_ref, destination_ref, force)?;
        if current.manifest.refs.get(destination_ref) == Some(&next_object) {
            return Ok(current.id);
        }

        let mut next_refs = current.manifest.refs.clone();
        next_refs.insert(destination_ref.to_owned(), next_object.clone());
        let mut exclusions = BTreeMap::new();
        if !non_fast_forward {
            for (reference, object) in &current.manifest.refs {
                if git::object_exists(repo, object)? {
                    exclusions.insert(reference.clone(), object.clone());
                }
            }
        }
        let pack_refs = BTreeMap::from([(destination_ref.to_owned(), next_object)]);
        let pack = git::create_incremental_pack(repo, &pack_refs, &exclusions)?;

        let next_key = random_key();
        let generation = current.manifest.generation + 1;
        let ordinal = 0;
        let pack_key = derive_subkey(
            &next_key,
            &current.manifest.repository_root,
            generation,
            SubkeyKind::Pack,
            ordinal,
        )?;
        let encrypted_pack = seal_with_key(
            &pack_key,
            &pack,
            &pack_aad(&current.manifest.repository_root, generation, ordinal),
        )?;
        let pack_id = object_id(&encrypted_pack);
        self.storage
            .put_object_if_absent(ObjectKind::Pack, &pack_id, &encrypted_pack)?;
        let descriptor = PackDescriptor {
            id: pack_id,
            plaintext_size: pack.len() as u64,
            generation,
            ordinal,
        };
        let predecessor_key_wrap = wrap_predecessor_key(
            &next_key,
            &current.generation_key,
            &current.manifest.repository_root,
            generation,
            &current.id,
        )?;
        let next = Manifest {
            format_version: current.manifest.format_version,
            repository_root: current.manifest.repository_root.clone(),
            generation,
            previous: Some(current.id.clone()),
            policy_id: current.policy.id.clone(),
            policy_generation: current.policy.body.generation,
            authorization: ManifestAuthorization::Writer,
            total_pack_count: current.manifest.total_pack_count + 1,
            refs: next_refs,
            new_packs: vec![descriptor],
            predecessor_key_wrap: Some(predecessor_key_wrap),
        };
        let next_id = self.commit_manifest(
            Some(&current),
            &current.policy,
            None,
            &next_key,
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
    ) -> Result<(OpenedState, String, bool)> {
        if !destination_ref.starts_with("refs/heads/") {
            bail!("only refs/heads/* destinations are supported")
        }
        git::ensure_repository(repo)?;
        let current = self.current_state()?;
        if !current.policy.is_active_writer(&self.key.device_id()?) {
            bail!("device is not an active writer")
        }
        if let Some(remote_name) = remote_name {
            self.validate_remote_continuity(repo, remote_name, &current)?;
        } else {
            // Direct callers do not have a clone-local pin, so validate the
            // complete signed and encrypted history before extending it.
            self.walk_chain(current.clone(), None)?;
        }
        let next_object = git::resolve_ref(repo, source_ref)?;
        if current.manifest.refs.get(destination_ref) == Some(&next_object) {
            return Ok((current, next_object, false));
        }
        let non_fast_forward = if let Some(old_object) = current.manifest.refs.get(destination_ref)
        {
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
        Ok((current, next_object, non_fast_forward))
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
        let current = self.current_state()?;
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(&current, &state)?;
        write_observed_client_state(&state_path, state, &current.id, &current.manifest)?;
        Ok(current.manifest)
    }

    pub fn import_packs(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let current = self.current_state()?;
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(&current, &state)?;

        let stop_generation = state.imported_generation;
        let chain = self.walk_chain(current.clone(), stop_generation)?;
        let mut imported: HashSet<String> = state.packs.into_iter().collect();
        for entry in chain.iter().rev() {
            if stop_generation == Some(entry.manifest.generation) {
                continue;
            }
            for descriptor in &entry.manifest.new_packs {
                if imported.contains(&descriptor.id) {
                    bail!(
                        "manifest delta reuses previously imported pack {}",
                        descriptor.id
                    )
                }
                let encrypted = self.storage.get_object(ObjectKind::Pack, &descriptor.id)?;
                if object_id(&encrypted) != descriptor.id {
                    bail!("pack ciphertext hash mismatch for {}", descriptor.id)
                }
                let pack_key = derive_subkey(
                    &entry.generation_key,
                    &entry.manifest.repository_root,
                    descriptor.generation,
                    SubkeyKind::Pack,
                    descriptor.ordinal,
                )?;
                let pack = open_with_key(
                    &pack_key,
                    &encrypted,
                    &pack_aad(
                        &entry.manifest.repository_root,
                        descriptor.generation,
                        descriptor.ordinal,
                    ),
                )?;
                if pack.len() as u64 != descriptor.plaintext_size {
                    bail!("pack plaintext size mismatch for {}", descriptor.id)
                }
                git::import_pack(repo, &pack)?;
                imported.insert(descriptor.id.clone());
            }
        }
        git::ensure_refs_connected(repo, &current.manifest.refs)?;
        write_client_state(&state_path, &imported, &current.id, &current.manifest)?;
        Ok(current.manifest)
    }

    fn validate_remote_continuity(
        &self,
        repo: &Path,
        remote_name: &str,
        current: &OpenedState,
    ) -> Result<()> {
        let state = read_client_state(&client_state_path(repo, remote_name)?)?;
        self.validate_pinned_head(current, &state)
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
        write_observed_client_state(&state_path, state, head_id, manifest)
    }

    fn validate_pinned_head(&self, current: &OpenedState, state: &ClientState) -> Result<()> {
        if let Some(root) = &state.repository_root
            && root != &current.manifest.repository_root
        {
            bail!("remote repository root changed")
        }
        if let Some(policy_generation) = state.policy_generation
            && current.manifest.policy_generation < policy_generation
        {
            bail!("remote policy rolled back")
        }
        let (Some(pinned_id), Some(pinned_generation)) =
            (state.head_id.as_deref(), state.generation)
        else {
            self.walk_chain(current.clone(), None)?;
            return Ok(());
        };
        if current.manifest.generation < pinned_generation {
            bail!(
                "remote manifest rolled back from generation {pinned_generation} to {}",
                current.manifest.generation
            )
        }
        let chain = self.walk_chain(current.clone(), Some(pinned_generation))?;
        let pinned = chain
            .last()
            .context("remote manifest chain ended before pinned generation")?;
        if pinned.id != pinned_id {
            bail!("remote manifest history forked from the locally pinned head")
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<Manifest> {
        let current = self.current_state()?;
        let chain = self.walk_chain(current.clone(), None)?;
        let mut count = 0_u64;
        for entry in chain.iter().rev() {
            for pack in &entry.manifest.new_packs {
                let encrypted = self.storage.get_object(ObjectKind::Pack, &pack.id)?;
                if object_id(&encrypted) != pack.id {
                    bail!("pack ciphertext hash mismatch for {}", pack.id)
                }
                let pack_key = derive_subkey(
                    &entry.generation_key,
                    &entry.manifest.repository_root,
                    pack.generation,
                    SubkeyKind::Pack,
                    pack.ordinal,
                )?;
                open_with_key(
                    &pack_key,
                    &encrypted,
                    &pack_aad(
                        &entry.manifest.repository_root,
                        pack.generation,
                        pack.ordinal,
                    ),
                )?;
                count += 1;
            }
        }
        if count != current.manifest.total_pack_count {
            bail!("manifest delta log pack count mismatch")
        }
        Ok(current.manifest)
    }

    pub fn current_manifest(&self) -> Result<(String, Manifest)> {
        let current = self.current_state()?;
        Ok((current.id, current.manifest))
    }

    fn current_state(&self) -> Result<OpenedState> {
        let head = self
            .storage
            .read_head()?
            .context("encrypted repository is not initialized")?;
        let (encrypted, header, policy, parent_policy) = self.read_manifest_material(&head)?;
        let generation_key = unwrap_generation_key(&header, &self.key)?;
        let manifest = open_manifest(&encrypted, &policy, parent_policy.as_ref(), &generation_key)?;
        if manifest.generation == 0 {
            manifest.validate_genesis(&policy)?;
        }
        Ok(OpenedState {
            id: head,
            manifest,
            header,
            policy,
            generation_key,
        })
    }

    fn walk_chain(
        &self,
        mut current: OpenedState,
        stop_generation: Option<u64>,
    ) -> Result<Vec<OpenedState>> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut seen_pack_ids = HashSet::new();
        loop {
            if !seen.insert(current.id.clone()) {
                bail!("manifest chain contains a cycle")
            }
            if stop_generation.is_some_and(|generation| current.manifest.generation < generation) {
                bail!("manifest chain skipped below requested generation")
            }
            for pack in &current.manifest.new_packs {
                if !seen_pack_ids.insert(pack.id.clone()) {
                    bail!("manifest chain repeats pack {}", pack.id)
                }
            }
            let should_stop = stop_generation == Some(current.manifest.generation);
            let is_genesis = current.manifest.generation == 0;
            chain.push(current.clone());
            if should_stop {
                break;
            }
            if is_genesis {
                if stop_generation.is_some() {
                    bail!("manifest chain ended before requested generation")
                }
                current.manifest.validate_genesis(&current.policy)?;
                break;
            }

            let previous_id = current
                .manifest
                .previous
                .clone()
                .context("manifest chain terminated above generation zero")?;
            let (encrypted, previous_header, previous_policy, previous_parent_policy) =
                self.read_manifest_material(&previous_id)?;
            let previous_key = unwrap_predecessor_key(
                &current.generation_key,
                &current.manifest,
                &previous_header,
            )?;
            let previous_manifest = open_manifest(
                &encrypted,
                &previous_policy,
                previous_parent_policy.as_ref(),
                &previous_key,
            )?;
            current.manifest.validate_successor(
                &previous_id,
                &previous_manifest,
                &current.policy,
            )?;
            current = OpenedState {
                id: previous_id,
                manifest: previous_manifest,
                header: previous_header,
                policy: previous_policy,
                generation_key: previous_key,
            };
        }
        Ok(chain)
    }

    fn read_manifest_material(
        &self,
        id: &str,
    ) -> Result<(Vec<u8>, ManifestHeader, PolicyState, Option<PolicyState>)> {
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
        let header = read_manifest_header(&bytes, &policy, parent.as_ref())?;
        Ok((bytes, header, policy, parent))
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
        previous: Option<&OpenedState>,
        policy: &PolicyState,
        parent_policy: Option<&PolicyState>,
        generation_key: &[u8; 32],
        authorization: ManifestAuthorization,
        manifest: Manifest,
    ) -> Result<String> {
        match previous {
            Some(previous) => {
                manifest.validate_successor(&previous.id, &previous.manifest, policy)?
            }
            None => manifest.validate_genesis(policy)?,
        }
        let encrypted = seal_manifest(
            &self.key,
            policy,
            generation_key,
            authorization,
            manifest.clone(),
        )?;
        let id = object_id(&encrypted);
        self.storage
            .put_object_if_absent(ObjectKind::Manifest, &id, &encrypted)?;

        let header = read_manifest_header(&encrypted, policy, parent_policy)?;
        let opened = open_manifest(&encrypted, policy, parent_policy, generation_key)?;
        if let Some(previous) = previous {
            let recovered = unwrap_predecessor_key(generation_key, &opened, &previous.header)?;
            if *recovered != *previous.generation_key {
                bail!("new manifest predecessor link did not recover the parent key")
            }
        }
        if header.generation != manifest.generation {
            bail!("new manifest self-check changed generation")
        }
        self.storage
            .compare_and_swap_head(previous.map(|state| state.id.as_str()), &id)?;
        Ok(id)
    }
}

fn transition_manifest(
    current: &OpenedState,
    policy: &PolicyState,
    generation_key: &[u8; 32],
) -> Result<Manifest> {
    let generation = current.manifest.generation + 1;
    Ok(Manifest {
        format_version: current.manifest.format_version,
        repository_root: current.manifest.repository_root.clone(),
        generation,
        previous: Some(current.id.clone()),
        policy_id: policy.id.clone(),
        policy_generation: policy.body.generation,
        authorization: ManifestAuthorization::PolicyTransition,
        total_pack_count: current.manifest.total_pack_count,
        refs: current.manifest.refs.clone(),
        new_packs: Vec::new(),
        predecessor_key_wrap: Some(wrap_predecessor_key(
            generation_key,
            &current.generation_key,
            &current.manifest.repository_root,
            generation,
            &current.id,
        )?),
    })
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
            let mut state: ClientState =
                serde_json::from_slice(&contents).context("parse git-remote-e2ee client state")?;
            // v2 client states used the observed generation as the import
            // checkpoint because observation and import were one operation.
            if state.format_version < 3 && state.imported_generation.is_none() {
                state.imported_generation = state.generation;
            }
            Ok(state)
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
        format_version: 3,
        packs: values,
        head_id: Some(head_id.to_owned()),
        generation: Some(manifest.generation),
        imported_generation: Some(manifest.generation),
        policy_generation: Some(manifest.policy_generation),
        repository_root: Some(manifest.repository_root.clone()),
    };
    persist_client_state(path, &state)
}

fn write_observed_client_state(
    path: &Path,
    previous: ClientState,
    head_id: &str,
    manifest: &Manifest,
) -> Result<()> {
    let state = ClientState {
        format_version: 3,
        packs: previous.packs,
        head_id: Some(head_id.to_owned()),
        generation: Some(manifest.generation),
        imported_generation: previous.imported_generation,
        policy_generation: Some(manifest.policy_generation),
        repository_root: Some(manifest.repository_root.clone()),
    };
    persist_client_state(path, &state)
}

fn persist_client_state(path: &Path, state: &ClientState) -> Result<()> {
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = path.with_extension(format!("json.{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(state)?)?;
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
