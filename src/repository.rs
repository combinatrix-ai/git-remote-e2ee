use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    KeyFile, PublicDevice, SecretKey, SubkeyKind, derive_subkey, object_id, open_pack_stream,
    random_key, seal_pack_stream,
};
use crate::git;
use crate::manifest::{
    Manifest, ManifestAuthorization, ManifestHeader, PackDescriptor, open_manifest, pack_aad,
    peek_manifest_header, seal_manifest, unwrap_generation_key, unwrap_predecessor_key,
    verify_manifest, wrap_predecessor_key,
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
    #[serde(default)]
    verified_refs: BTreeMap<String, String>,
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
        let generation_key = random_key();
        let genesis = Manifest::genesis(self.key.repository_root.clone(), &policy, policy_bytes);
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
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?.clone();
        self.validate_pinned_head(&chain, &read_client_state(pin_path)?)?;
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
        let next = transition_manifest(&current, &next_policy, policy_bytes, &next_key)?;
        let result =
            self.publish_policy_transition(&current, &next_policy, &next_key, next.clone())?;
        write_client_state(
            pin_path,
            &HashSet::new(),
            &result.0,
            &next,
            &BTreeMap::new(),
        )?;
        Ok(result)
    }

    pub fn revoke_device(&self, device_id: &str, pin_path: &Path) -> Result<(String, String)> {
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?.clone();
        self.validate_pinned_head(&chain, &read_client_state(pin_path)?)?;
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
        let next = transition_manifest(&current, &next_policy, policy_bytes, &next_key)?;
        let result =
            self.publish_policy_transition(&current, &next_policy, &next_key, next.clone())?;
        write_client_state(
            pin_path,
            &HashSet::new(),
            &result.0,
            &next,
            &BTreeMap::new(),
        )?;
        Ok(result)
    }

    pub fn pin_admin_state(&self, pin_path: &Path) -> Result<()> {
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?;
        let previous = read_client_state(pin_path)?;
        self.validate_pinned_head(&chain, &previous)?;
        write_client_state(
            pin_path,
            &HashSet::new(),
            &current.id,
            &current.manifest,
            &BTreeMap::new(),
        )
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        Ok(self
            .current_chain()?
            .into_iter()
            .next()
            .context("manifest chain is empty")?
            .policy
            .body
            .devices)
    }

    fn publish_policy_transition(
        &self,
        current: &OpenedState,
        policy: &PolicyState,
        generation_key: &[u8; 32],
        manifest: Manifest,
    ) -> Result<(String, String)> {
        policy.validate_successor(&current.policy)?;
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
        let mut pack_source = git::start_incremental_pack(repo, &pack_refs, &exclusions)?;
        let mut pack_stage = self.storage.begin_object(ObjectKind::Pack)?;
        let sealed = seal_pack_stream(
            &pack_key,
            &mut pack_source,
            &mut pack_stage,
            &pack_aad(&current.manifest.repository_root, generation, ordinal),
        )?;
        pack_source.finish()?;
        pack_stage.finish(&sealed.object_id)?;
        let descriptor = PackDescriptor {
            id: sealed.object_id,
            plaintext_size: sealed.plaintext_size,
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
            introduced_policy: None,
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
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?.clone();
        let device_id = self.key.device_id()?;
        if !current.policy.is_active_writer(&device_id) {
            if current.policy.is_active_reader(&device_id) {
                if let Some(remote_name) = remote_name {
                    bail!(
                        "this device is read-only for {remote_name}; ask an administrator for the write role"
                    )
                }
                bail!("this device is read-only; ask an administrator for the write role")
            }
            bail!("device is not an active writer")
        }
        if let Some(remote_name) = remote_name {
            self.validate_remote_continuity(repo, remote_name, &chain)?;
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
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?.clone();
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(&chain, &state)?;
        write_observed_client_state(&state_path, state, &current.id, &current.manifest)?;
        Ok(current.manifest.clone())
    }

    pub fn import_packs(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?.clone();
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(&chain, &state)?;

        let stop_generation = state.imported_generation;
        let mut imported: HashSet<String> = state.packs.into_iter().collect();
        for entry in chain.iter().rev() {
            if stop_generation.is_some_and(|generation| entry.manifest.generation <= generation) {
                continue;
            }
            for descriptor in &entry.manifest.new_packs {
                if imported.contains(&descriptor.id) {
                    bail!(
                        "manifest delta reuses previously imported pack {}",
                        descriptor.id
                    )
                }
                let encrypted = self.storage.open_object(ObjectKind::Pack, &descriptor.id)?;
                let pack_key = derive_subkey(
                    &entry.generation_key,
                    &entry.manifest.repository_root,
                    descriptor.generation,
                    SubkeyKind::Pack,
                    descriptor.ordinal,
                )?;
                let mut importer = git::start_pack_import(repo)?;
                open_pack_stream(
                    &pack_key,
                    encrypted,
                    &mut importer,
                    &pack_aad(
                        &entry.manifest.repository_root,
                        descriptor.generation,
                        descriptor.ordinal,
                    ),
                    descriptor.plaintext_size,
                    &descriptor.id,
                )?;
                importer.finish()?;
                imported.insert(descriptor.id.clone());
            }
        }
        git::ensure_refs_connected_since(repo, &current.manifest.refs, &state.verified_refs)?;
        write_client_state(
            &state_path,
            &imported,
            &current.id,
            &current.manifest,
            &current.manifest.refs,
        )?;
        Ok(current.manifest)
    }

    fn validate_remote_continuity(
        &self,
        repo: &Path,
        remote_name: &str,
        chain: &[OpenedState],
    ) -> Result<()> {
        let state = read_client_state(&client_state_path(repo, remote_name)?)?;
        self.validate_pinned_head(chain, &state)
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

    fn validate_pinned_head(&self, chain: &[OpenedState], state: &ClientState) -> Result<()> {
        let current = chain.first().context("manifest chain is empty")?;
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
            return Ok(());
        };
        if current.manifest.generation < pinned_generation {
            bail!(
                "remote manifest rolled back from generation {pinned_generation} to {}",
                current.manifest.generation
            )
        }
        let pinned = chain
            .iter()
            .find(|entry| entry.manifest.generation == pinned_generation)
            .context("remote manifest chain ended before pinned generation")?;
        if pinned.id != pinned_id {
            bail!("remote manifest history forked from the locally pinned head")
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<Manifest> {
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?;
        let mut count = 0_u64;
        for entry in chain.iter().rev() {
            for pack in &entry.manifest.new_packs {
                let encrypted = self.storage.open_object(ObjectKind::Pack, &pack.id)?;
                let pack_key = derive_subkey(
                    &entry.generation_key,
                    &entry.manifest.repository_root,
                    pack.generation,
                    SubkeyKind::Pack,
                    pack.ordinal,
                )?;
                open_pack_stream(
                    &pack_key,
                    encrypted,
                    io::sink(),
                    &pack_aad(
                        &entry.manifest.repository_root,
                        pack.generation,
                        pack.ordinal,
                    ),
                    pack.plaintext_size,
                    &pack.id,
                )?;
                count += 1;
            }
        }
        if count != current.manifest.total_pack_count {
            bail!("manifest delta log pack count mismatch")
        }
        Ok(current.manifest.clone())
    }

    pub fn current_manifest(&self) -> Result<(String, Manifest)> {
        let current = self
            .current_chain()?
            .into_iter()
            .next()
            .context("manifest chain is empty")?;
        Ok((current.id, current.manifest))
    }

    fn current_chain(&self) -> Result<Vec<OpenedState>> {
        let head = self
            .storage
            .read_head()?
            .context("encrypted repository is not initialized")?;
        let (mut id, mut encrypted, mut header) = self.read_manifest_material(&head)?;
        let mut generation_key = unwrap_generation_key(&header, &self.key)?;
        let mut opened = open_manifest(&encrypted, &generation_key)?;
        let mut unverified = Vec::new();
        let mut seen = HashSet::new();

        loop {
            if !seen.insert(id.clone()) {
                bail!("manifest chain contains a cycle")
            }
            let Some(previous_id) = opened.manifest.previous.clone() else {
                if opened.manifest.generation != 0 {
                    bail!("manifest chain terminated above generation zero")
                }
                unverified.push((id, opened, generation_key));
                break;
            };
            let (parent_id, parent_encrypted, parent_header) =
                self.read_manifest_material(&previous_id)?;
            let parent_key =
                unwrap_predecessor_key(&generation_key, &opened.manifest, &parent_header)?;
            unverified.push((id, opened, generation_key));
            id = parent_id;
            encrypted = parent_encrypted;
            header = parent_header;
            generation_key = parent_key;
            opened = open_manifest(&encrypted, &generation_key)?;
            if opened.header != header {
                bail!("predecessor manifest header changed while opening")
            }
        }

        let mut chain_oldest_first: Vec<OpenedState> = Vec::with_capacity(unverified.len());
        let mut seen_pack_ids = HashSet::new();
        for (index, (id, opened, generation_key)) in unverified.into_iter().rev().enumerate() {
            let manifest = &opened.manifest;
            for pack in &manifest.new_packs {
                if !seen_pack_ids.insert(pack.id.clone()) {
                    bail!("manifest chain repeats pack {}", pack.id)
                }
            }
            let (policy, parent_policy) = if index == 0 {
                let policy_bytes = manifest
                    .introduced_policy
                    .as_deref()
                    .context("genesis manifest is missing its introduced policy")?;
                let policy = PolicyState::parse(policy_bytes)?;
                policy.validate_genesis(&self.key.repository_root)?;
                manifest.validate_genesis(&policy)?;
                (policy, None)
            } else {
                let parent = chain_oldest_first
                    .last()
                    .context("manifest parent is missing")?;
                let (policy, parent_policy) = match manifest.authorization {
                    ManifestAuthorization::Writer => {
                        if manifest.introduced_policy.is_some() {
                            bail!("ordinary manifest unexpectedly introduces a policy")
                        }
                        (parent.policy.clone(), None)
                    }
                    ManifestAuthorization::PolicyTransition => {
                        let bytes = manifest
                            .introduced_policy
                            .as_deref()
                            .context("policy transition is missing its introduced policy")?;
                        let policy = PolicyState::parse(bytes)?;
                        policy.validate_successor(&parent.policy)?;
                        (policy, Some(parent.policy.clone()))
                    }
                    ManifestAuthorization::Checkpoint => {
                        bail!("checkpoint transitions are reserved but not implemented")
                    }
                };
                manifest.validate_successor(&parent.id, &parent.manifest, &policy)?;
                (policy, parent_policy)
            };
            verify_manifest(&opened, &policy, parent_policy.as_ref(), &generation_key)?;
            chain_oldest_first.push(OpenedState {
                id,
                manifest: opened.manifest,
                header: opened.header,
                policy,
                generation_key,
            });
        }
        chain_oldest_first.reverse();
        Ok(chain_oldest_first)
    }

    fn read_manifest_material(&self, id: &str) -> Result<(String, Vec<u8>, ManifestHeader)> {
        let bytes = self.storage.get_object(ObjectKind::Manifest, id)?;
        if object_id(&bytes) != id {
            bail!("manifest ciphertext hash mismatch")
        }
        let header = peek_manifest_header(&bytes)?;
        Ok((id.to_owned(), bytes, header))
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

        let opened = open_manifest(&encrypted, generation_key)?;
        verify_manifest(&opened, policy, parent_policy, generation_key)?;
        if let Some(previous) = previous {
            let recovered =
                unwrap_predecessor_key(generation_key, &opened.manifest, &previous.header)?;
            if *recovered != *previous.generation_key {
                bail!("new manifest predecessor link did not recover the parent key")
            }
        }
        if opened.header.generation != manifest.generation {
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
    policy_bytes: Vec<u8>,
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
        introduced_policy: Some(policy_bytes),
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
    crate::persist::create_dir_all_durable(&directory)
        .with_context(|| format!("create {}", directory.display()))?;
    Ok(directory.join("state.json"))
}

fn read_client_state(path: &Path) -> Result<ClientState> {
    match fs::read(path) {
        Ok(contents) => {
            let state: ClientState =
                serde_json::from_slice(&contents).context("parse git-remote-e2ee client state")?;
            if state.format_version != 5 {
                bail!(
                    "unsupported git-remote-e2ee client state format {}",
                    state.format_version
                )
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
    verified_refs: &BTreeMap<String, String>,
) -> Result<()> {
    let mut values: Vec<_> = values.iter().cloned().collect();
    values.sort();
    let state = ClientState {
        format_version: 5,
        packs: values,
        head_id: Some(head_id.to_owned()),
        generation: Some(manifest.generation),
        imported_generation: Some(manifest.generation),
        policy_generation: Some(manifest.policy_generation),
        repository_root: Some(manifest.repository_root.clone()),
        verified_refs: verified_refs.clone(),
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
        format_version: 5,
        packs: previous.packs,
        head_id: Some(head_id.to_owned()),
        generation: Some(manifest.generation),
        imported_generation: previous.imported_generation,
        policy_generation: Some(manifest.policy_generation),
        repository_root: Some(manifest.repository_root.clone()),
        verified_refs: previous.verified_refs,
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
    crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_FILE_FLUSH);
    fs::rename(&temporary, path)?;
    crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_NAME_PUBLISH);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("client state path has no parent")?;
    crate::persist::sync_directory(parent)
        .with_context(|| format!("sync directory {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn testing_write_client_state(
    path: &Path,
    head_id: &str,
    generation: u64,
) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        crate::persist::create_dir_all_durable(parent)?;
    }
    let state = ClientState {
        format_version: 5,
        packs: Vec::new(),
        head_id: Some(head_id.to_owned()),
        generation: Some(generation),
        imported_generation: Some(generation),
        policy_generation: Some(1),
        repository_root: Some("durability-fixture".to_owned()),
        verified_refs: BTreeMap::new(),
    };
    persist_client_state(path, &state)
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

#[cfg(test)]
mod tests {
    use super::ClientState;

    #[test]
    fn client_state_without_verified_frontier_requires_a_full_check() {
        let legacy = br#"{
            "format_version": 4,
            "packs": ["pack-id"],
            "head_id": "head-id",
            "generation": 7,
            "imported_generation": 7,
            "policy_generation": 2,
            "repository_root": "repository-root"
        }"#;
        let state: ClientState = serde_json::from_slice(legacy).unwrap();
        assert!(state.verified_refs.is_empty());
    }
}
