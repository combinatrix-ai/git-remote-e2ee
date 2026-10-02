use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
use crate::storage::{HeadObservation, ObjectKind, Storage};
use crate::trace;

const MAX_RECOVERY_OUTER_COMMITS: usize = 2048;
const MAX_RECOVERY_CANDIDATES: usize = 256;
const MAX_RECOVERY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECOVERY_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECOVERY_CRYPTO_OPERATIONS: u64 = 1_000_000;
const MAX_REJECTED_HEADS: usize = 16;
const STALE_FLOOR_WARNING: &str = "Updates after this floor may be omitted. This may also omit revocations and disclose subsequently published content to devices excluded by a newer policy.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryClass {
    Valid,
    Invalid,
    Unverifiable,
    Unsupported,
    Unavailable,
    Discontinuous,
}

impl RecoveryClass {
    pub fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unverifiable => "unverifiable",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::Discontinuous => "discontinuous",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryCandidate {
    pub manifest_id: String,
    pub generation: u64,
    pub outer_commit: Option<String>,
    pub verified_signer: String,
}

#[derive(Clone, Debug)]
pub struct RecoveryReport {
    pub classification: RecoveryClass,
    pub reason: String,
    pub head_id: Option<String>,
    pub claimed_signer: Option<String>,
    pub floor_id: Option<String>,
    pub floor_generation: Option<u64>,
    pub candidates: Vec<RecoveryCandidate>,
    pub default_base: Option<String>,
    pub replays: Vec<String>,
    pub conflict: bool,
    pub freshness_unverified: bool,
    pub warning: Option<String>,
    pub blocked_reason: Option<String>,
    pub published_manifest: Option<String>,
}

pub struct RecoveryOptions<'a> {
    pub publish: bool,
    pub base: Option<&'a str>,
    pub discard_newer: bool,
    pub accept_stale_floor: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ClientState {
    #[serde(default)]
    format_version: u64,
    #[serde(default)]
    packs: Vec<String>,
    // Continuity floor: imported and connectivity-verified, or our own CAS winner.
    head_id: Option<String>,
    generation: Option<u64>,
    // The last generation whose pack deltas and advertised refs we imported and checked.
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
    verified_signer: String,
}

struct CommitHead<'a> {
    previous: Option<&'a OpenedState>,
    observation: Option<&'a HeadObservation>,
}

struct ClientStateLock {
    _file: File,
}

struct RecoveryBudget {
    crypto_operations: u64,
    bytes_read: u64,
}

impl RecoveryBudget {
    fn charge_manifest(&mut self, header: &ManifestHeader, byte_count: usize) -> Result<()> {
        self.bytes_read = self
            .bytes_read
            .checked_add(byte_count as u64)
            .context("recovery byte budget overflow")?;
        if self.bytes_read > MAX_RECOVERY_BYTES {
            bail!("recovery manifest byte budget exhausted")
        }
        let operations = (header.generation_key_envelopes.len() as u64)
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .context("recovery crypto budget overflow")?;
        self.crypto_operations = self
            .crypto_operations
            .checked_add(operations)
            .context("recovery crypto budget overflow")?;
        if self.crypto_operations > MAX_RECOVERY_CRYPTO_OPERATIONS {
            bail!("recovery cryptographic-operation budget exhausted")
        }
        Ok(())
    }
}

impl ClientStateLock {
    fn acquire(path: &Path) -> Result<Self> {
        // Lock a stable sibling: persist_client_state atomically replaces the state file.
        let lock_path = path.with_extension("json.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open client state lock {}", lock_path.display()))?;
        FileExt::lock_exclusive(&file)
            .with_context(|| format!("lock client state {}", path.display()))?;
        Ok(Self { _file: file })
    }
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
        let _pin_lock = ClientStateLock::acquire(pin_path)?;
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
        write_client_state_locked(
            pin_path,
            &HashSet::new(),
            &result.0,
            &next,
            &BTreeMap::new(),
        )?;
        Ok(result)
    }

    pub fn revoke_device(&self, device_id: &str, pin_path: &Path) -> Result<(String, String)> {
        let _pin_lock = ClientStateLock::acquire(pin_path)?;
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
        write_client_state_locked(
            pin_path,
            &HashSet::new(),
            &result.0,
            &next,
            &BTreeMap::new(),
        )?;
        Ok(result)
    }

    pub fn pin_admin_state(&self, pin_path: &Path) -> Result<()> {
        let _pin_lock = ClientStateLock::acquire(pin_path)?;
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?;
        let previous = read_client_state(pin_path)?;
        self.validate_pinned_head(&chain, &previous)?;
        write_client_state_locked(
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

    pub fn delete_ref(&self, repo: &Path, destination_ref: &str) -> Result<String> {
        self.change_ref_inner(repo, None, None, destination_ref, false)
    }

    pub fn delete_ref_for_remote(
        &self,
        repo: &Path,
        remote_name: &str,
        destination_ref: &str,
    ) -> Result<String> {
        self.change_ref_inner(repo, Some(remote_name), None, destination_ref, false)
    }

    fn push_update_inner(
        &self,
        repo: &Path,
        remote_name: Option<&str>,
        source_ref: &str,
        destination_ref: &str,
        force: bool,
    ) -> Result<String> {
        self.change_ref_inner(repo, remote_name, Some(source_ref), destination_ref, force)
    }

    fn change_ref_inner(
        &self,
        repo: &Path,
        remote_name: Option<&str>,
        source_ref: Option<&str>,
        destination_ref: &str,
        force: bool,
    ) -> Result<String> {
        let state_path = remote_name
            .map(|name| client_state_path(repo, name))
            .transpose()?;
        let _state_lock = state_path
            .as_deref()
            .map(ClientStateLock::acquire)
            .transpose()?;
        let (current, next_object, non_fast_forward) = self.preflight_ref_change(
            repo,
            remote_name,
            state_path.as_deref(),
            source_ref,
            destination_ref,
            force,
        )?;
        if next_object
            .as_ref()
            .is_some_and(|next| current.manifest.refs.get(destination_ref) == Some(next))
        {
            return Ok(current.id);
        }

        let mut next_refs = current.manifest.refs.clone();
        if let Some(next_object) = &next_object {
            next_refs.insert(destination_ref.to_owned(), next_object.clone());
        } else {
            next_refs.remove(destination_ref);
        }

        let next_key = random_key();
        let generation = current.manifest.generation + 1;
        let mut new_packs = Vec::new();
        let mut total_pack_count = current.manifest.total_pack_count;
        if let Some(next_object) = next_object {
            let mut exclusions = BTreeMap::new();
            if !non_fast_forward {
                for (reference, object) in &current.manifest.refs {
                    if git::object_exists(repo, object)? {
                        exclusions.insert(reference.clone(), object.clone());
                    }
                }
            }
            let pack_refs = BTreeMap::from([(destination_ref.to_owned(), next_object)]);
            let ordinal = 0;
            let pack_key = derive_subkey(
                &next_key,
                &current.manifest.repository_root,
                generation,
                SubkeyKind::Pack,
                ordinal,
            )?;
            let pack_timer = trace::Span::new("inner_pack_encrypt_and_store");
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
            drop(pack_timer);
            new_packs.push(PackDescriptor {
                id: sealed.object_id,
                plaintext_size: sealed.plaintext_size,
                generation,
                ordinal,
            });
            total_pack_count += 1;
        }
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
            total_pack_count,
            refs: next_refs,
            new_packs,
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
        if let Some(state_path) = state_path.as_deref() {
            self.pin_manifest_locked(state_path, &next_id, &next)?;
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
        self.preflight_ref_change(repo, None, None, Some(source_ref), destination_ref, force)?;
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
        let state_path = client_state_path(repo, remote_name)?;
        let _state_lock = ClientStateLock::acquire(&state_path)?;
        self.preflight_ref_change(
            repo,
            Some(remote_name),
            Some(&state_path),
            Some(source_ref),
            destination_ref,
            force,
        )?;
        Ok(())
    }

    pub fn validate_delete_ref_for_remote(
        &self,
        repo: &Path,
        remote_name: &str,
        destination_ref: &str,
    ) -> Result<()> {
        let state_path = client_state_path(repo, remote_name)?;
        let _state_lock = ClientStateLock::acquire(&state_path)?;
        self.preflight_ref_change(
            repo,
            Some(remote_name),
            Some(&state_path),
            None,
            destination_ref,
            false,
        )?;
        Ok(())
    }

    fn preflight_ref_change(
        &self,
        repo: &Path,
        remote_name: Option<&str>,
        state_path: Option<&Path>,
        source_ref: Option<&str>,
        destination_ref: &str,
        force: bool,
    ) -> Result<(OpenedState, Option<String>, bool)> {
        git::ensure_repository(repo)?;
        let ref_kind = git::validate_inner_ref(repo, destination_ref)?;
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
        if remote_name.is_some() {
            let state_path = state_path.context("remote client state path is missing")?;
            self.validate_remote_continuity(state_path, &chain)?;
        }
        for reference in current.manifest.refs.keys() {
            git::validate_inner_ref(repo, reference)?;
        }
        let old_object = current.manifest.refs.get(destination_ref);
        let Some(source_ref) = source_ref else {
            if old_object.is_none() {
                bail!("remote ref {destination_ref} does not exist")
            }
            if destination_ref == "refs/heads/main" {
                bail!(
                    "cannot delete refs/heads/main because it is advertised as the remote default branch"
                )
            }
            return Ok((current, None, false));
        };

        let next_object = git::resolve_ref(repo, source_ref)?;
        if old_object == Some(&next_object) {
            return Ok((current, Some(next_object), false));
        }
        if ref_kind == git::InnerRefKind::Branch {
            git::ensure_branch_target(repo, destination_ref, &next_object)?;
        }
        if ref_kind == git::InnerRefKind::Tag && old_object.is_some() && !force {
            bail!("tag {destination_ref} already exists; use --force to move it")
        }
        let non_fast_forward = if ref_kind == git::InnerRefKind::Branch
            && let Some(old_object) = old_object
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
        Ok((current, Some(next_object), non_fast_forward))
    }

    pub fn fetch_into(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let state_path = client_state_path(repo, remote_name)?;
        let _state_lock = ClientStateLock::acquire(&state_path)?;
        let manifest = self.import_packs_locked(repo, &state_path)?;
        for (reference, object) in &manifest.refs {
            match git::validate_inner_ref(repo, reference)? {
                git::InnerRefKind::Branch => {
                    let short = reference.strip_prefix("refs/heads/").unwrap();
                    git::update_ref(repo, &format!("refs/remotes/{remote_name}/{short}"), object)?;
                }
                git::InnerRefKind::Tag => git::update_ref(repo, reference, object)?,
            }
        }
        Ok(manifest)
    }

    pub fn observe_manifest(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let state_path = client_state_path(repo, remote_name)?;
        let _state_lock = ClientStateLock::acquire(&state_path)?;
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?.clone();
        for reference in current.manifest.refs.keys() {
            git::validate_inner_ref(repo, reference)?;
        }
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(&chain, &state)?;
        // Git skips the helper's fetch command when every advertised object is
        // already local, for example after a membership change, a deletion, or
        // a tag that points at an existing object. Advance the floor here only
        // when the advertised refs are fully connected locally, which is the
        // same check a fetch would finish with; authentication alone never
        // moves it. Earlier packs are not needed once these refs are
        // connected, because later packs are built against these tips.
        if git::ensure_refs_connected_since(repo, &current.manifest.refs, &state.verified_refs)
            .is_ok()
        {
            let packs: HashSet<String> = state.packs.iter().cloned().collect();
            write_client_state_locked(
                &state_path,
                &packs,
                &current.id,
                &current.manifest,
                &current.manifest.refs,
            )?;
        }
        Ok(current.manifest.clone())
    }

    pub fn import_packs(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let state_path = client_state_path(repo, remote_name)?;
        let _state_lock = ClientStateLock::acquire(&state_path)?;
        self.import_packs_locked(repo, &state_path)
    }

    fn import_packs_locked(&self, repo: &Path, state_path: &Path) -> Result<Manifest> {
        let chain = self.current_chain()?;
        let current = chain.first().context("manifest chain is empty")?.clone();
        for reference in current.manifest.refs.keys() {
            git::validate_inner_ref(repo, reference)?;
        }
        let state = read_client_state(state_path)?;
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
                let decrypt_timer = trace::Span::new("pack_decrypt_to_index_pack");
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
                drop(decrypt_timer);
                importer.finish()?;
                imported.insert(descriptor.id.clone());
            }
        }
        let connectivity_timer = trace::Span::new("inner_ref_connectivity_check");
        git::ensure_refs_connected_since(repo, &current.manifest.refs, &state.verified_refs)?;
        drop(connectivity_timer);
        write_client_state_locked(
            state_path,
            &imported,
            &current.id,
            &current.manifest,
            &current.manifest.refs,
        )?;
        Ok(current.manifest)
    }

    fn validate_remote_continuity(&self, state_path: &Path, chain: &[OpenedState]) -> Result<()> {
        let state = read_client_state(state_path)?;
        self.validate_pinned_head(chain, &state)
    }

    fn pin_manifest_locked(
        &self,
        state_path: &Path,
        head_id: &str,
        manifest: &Manifest,
    ) -> Result<()> {
        let state = read_client_state(state_path)?;
        write_published_client_state_locked(state_path, state, head_id, manifest)
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

    pub fn recover(
        &self,
        repo: &Path,
        remote_name: &str,
        options: RecoveryOptions<'_>,
    ) -> Result<RecoveryReport> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let state_path = client_state_path(repo, remote_name)?;
        let _state_lock = ClientStateLock::acquire(&state_path)?;
        let state = read_client_state(&state_path)?;
        let mut report = RecoveryReport {
            classification: RecoveryClass::Unavailable,
            reason: "could not read the storage head".to_owned(),
            head_id: None,
            claimed_signer: None,
            floor_id: state.head_id.clone(),
            floor_generation: state.generation,
            candidates: Vec::new(),
            default_base: None,
            replays: Vec::new(),
            conflict: false,
            freshness_unverified: state.head_id.is_none() || state.generation.is_none(),
            warning: None,
            blocked_reason: None,
            published_manifest: None,
        };
        let observation = match self.storage.observe_head() {
            Ok(observation) => observation,
            Err(error) => {
                if format!("{error:#}").contains("budget exhausted") {
                    return Err(error).context("bounded recovery discovery failed");
                }
                report.reason = format!("storage head is unavailable: {error:#}");
                if options.publish {
                    report.blocked_reason = Some(report.reason.clone());
                }
                return Ok(report);
            }
        };
        report.head_id = observation.head_id.clone();
        let mut budget = RecoveryBudget {
            crypto_operations: 0,
            bytes_read: 0,
        };
        let current_chain = match observation.head_id.as_deref() {
            Some(head) => self.chain_from(
                head,
                &mut |id| self.read_manifest_material(id),
                Some(&mut budget),
            ),
            None if observation.head_bytes.is_some() => Err(anyhow::anyhow!(
                "storage HEAD is not a valid manifest object ID"
            )),
            None => Err(anyhow::anyhow!("encrypted repository has no storage HEAD")),
        };
        match current_chain {
            Ok(chain) => {
                report.claimed_signer = chain.first().map(|entry| entry.verified_signer.clone());
                if state.head_id.is_some() && state.generation.is_some() {
                    match self.validate_pinned_head(&chain, &state) {
                        Ok(()) => match self.check_chain_ciphertext_presence(&chain) {
                            Ok(()) => {
                                report.classification = RecoveryClass::Valid;
                                report.reason =
                                        "storage head is authenticated and continuous with the local floor"
                                            .to_owned();
                            }
                            Err(error) => {
                                report.classification = RecoveryClass::Unavailable;
                                report.reason = format!(
                                    "authenticated storage head has unavailable ciphertext: {error:#}"
                                );
                            }
                        },
                        Err(error) => {
                            report.classification = RecoveryClass::Discontinuous;
                            report.reason =
                                format!("authenticated storage head is discontinuous: {error:#}");
                        }
                    }
                } else {
                    match self.check_chain_ciphertext_presence(&chain) {
                        Ok(()) => {
                            report.classification = RecoveryClass::Valid;
                            report.reason =
                                "storage head is authenticated, but this client has no continuity floor"
                                    .to_owned();
                        }
                        Err(error) => {
                            report.classification = RecoveryClass::Unavailable;
                            report.reason = format!(
                                "authenticated storage head has unavailable ciphertext: {error:#}"
                            );
                        }
                    }
                    report.freshness_unverified = true;
                }
            }
            Err(error) => {
                if format!("{error:#}").contains("budget exhausted") {
                    return Err(error).context("bounded recovery discovery failed");
                }
                let (class, reason) =
                    classify_recovery_error(&error, observation.head_bytes.as_deref());
                report.classification = class;
                report.reason = reason;
                if class == RecoveryClass::Invalid
                    && let Some(head) = observation.head_id.as_deref()
                {
                    report.claimed_signer = self.claimed_signer_for_head(head).ok();
                }
            }
        }

        if report.classification == RecoveryClass::Invalid {
            let evidence_id = observation.head_id.clone().unwrap_or_else(|| {
                hex::encode(Sha256::digest(
                    observation.head_bytes.as_deref().unwrap_or_default(),
                ))
            });
            record_rejected_head(
                &state_path,
                &evidence_id,
                report.classification,
                &report.reason,
            )?;
        } else {
            report.blocked_reason = Some(match report.classification {
                RecoveryClass::Valid => {
                    "the storage head is already valid; recovery is not needed".to_owned()
                }
                RecoveryClass::Unverifiable => {
                    "the storage head cannot be opened by this device; recovery is forbidden"
                        .to_owned()
                }
                RecoveryClass::Unsupported => {
                    "the storage head uses an unsupported format; recovery is forbidden".to_owned()
                }
                RecoveryClass::Unavailable => {
                    "required storage data is unavailable; recovery is forbidden".to_owned()
                }
                RecoveryClass::Discontinuous => {
                    "the storage head is discontinuous with the local floor; recovery is forbidden"
                        .to_owned()
                }
                RecoveryClass::Invalid => unreachable!(),
            });
            return Ok(report);
        }

        let (Some(floor_id), Some(floor_generation)) = (state.head_id.as_deref(), state.generation)
        else {
            report.freshness_unverified = true;
            report.blocked_reason = Some(
                "this repository has no authenticated continuity floor; freshness and fork identity are unverified".to_owned(),
            );
            return Ok(report);
        };

        let history = self
            .storage
            .recovery_history(MAX_RECOVERY_OUTER_COMMITS, MAX_RECOVERY_MANIFEST_BYTES)?;
        let carrier_history = history.is_some();
        let history = history.unwrap_or_default();
        if history.commits.len() > MAX_RECOVERY_OUTER_COMMITS {
            bail!("recovery outer-commit budget exhausted")
        }
        let historical_bytes = history.manifests.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(bytes.len() as u64)
                .context("recovery manifest byte budget overflow")
        })?;
        if historical_bytes > MAX_RECOVERY_MANIFEST_BYTES {
            bail!("recovery manifest byte budget exhausted")
        }
        budget.bytes_read = budget
            .bytes_read
            .checked_add(historical_bytes)
            .context("recovery manifest byte budget overflow")?;
        if budget.bytes_read > MAX_RECOVERY_BYTES {
            bail!("recovery manifest byte budget exhausted")
        }
        if carrier_history
            && !history
                .commits
                .iter()
                .any(|commit| commit.head_id.as_deref() == Some(floor_id))
        {
            report.blocked_reason = Some(format!(
                "carrier history does not contain the pinned floor manifest {floor_id}; refusing discontinuous recovery"
            ));
            report.classification = RecoveryClass::Discontinuous;
            return Ok(report);
        }

        let read_history_material = |id: &str| -> Result<(String, Vec<u8>, ManifestHeader)> {
            match self.read_manifest_material(id) {
                Ok(material) => Ok(material),
                Err(current_error) => {
                    let bytes = history.manifests.get(id).with_context(|| {
                        format!("historical manifest {id} is unavailable (current read: {current_error:#})")
                    })?;
                    if object_id(bytes) != id {
                        bail!("historical manifest {id} content ID mismatch")
                    }
                    let header = peek_manifest_header(bytes)?;
                    Ok((id.to_owned(), bytes.clone(), header))
                }
            }
        };
        let floor_chain = match self.chain_from(
            floor_id,
            &mut |id| read_history_material(id),
            Some(&mut budget),
        ) {
            Ok(chain) => chain,
            Err(error) => {
                report.blocked_reason = Some(format!(
                    "pinned floor is unavailable or cannot be authenticated: {error:#}"
                ));
                return Ok(report);
            }
        };
        let floor = match floor_chain
            .iter()
            .find(|entry| entry.id == floor_id && entry.manifest.generation == floor_generation)
        {
            Some(floor) => floor,
            None => {
                report.blocked_reason = Some(
                    "client state floor does not match its authenticated manifest generation"
                        .to_owned(),
                );
                return Ok(report);
            }
        };
        if state
            .repository_root
            .as_deref()
            .is_some_and(|root| root != floor.manifest.repository_root)
            || state
                .policy_generation
                .is_some_and(|generation| generation > floor.manifest.policy_generation)
        {
            report.blocked_reason = Some(
                "client state floor metadata does not match the authenticated floor".to_owned(),
            );
            return Ok(report);
        }
        let floor_candidate = RecoveryCandidate {
            manifest_id: floor.id.clone(),
            generation: floor.manifest.generation,
            outer_commit: history
                .commits
                .iter()
                .find(|commit| commit.head_id.as_deref() == Some(floor_id))
                .map(|commit| commit.commit_id.clone()),
            verified_signer: floor.verified_signer.clone(),
        };

        let mut replay_ids = BTreeSet::new();
        let mut seen_head_ids = HashSet::new();
        let mut descendants: Vec<(RecoveryCandidate, Vec<OpenedState>)> = Vec::new();
        if carrier_history {
            let mut unique_heads = Vec::new();
            for commit in &history.commits {
                if let Some(head) = &commit.head_id {
                    if seen_head_ids.insert(head.clone()) {
                        unique_heads.push((head, commit));
                    } else {
                        replay_ids.insert(head.clone());
                    }
                }
            }
            if unique_heads.len() > MAX_RECOVERY_CANDIDATES {
                bail!("recovery candidate budget exhausted")
            }
            for (candidate_id, commit) in unique_heads {
                if candidate_id == floor_id {
                    continue;
                }
                let candidate_chain = match self.chain_from(
                    candidate_id,
                    &mut |id| read_history_material(id),
                    Some(&mut budget),
                ) {
                    Ok(chain) => chain,
                    Err(error) => {
                        let (class, _) = classify_recovery_error(&error, None);
                        match class {
                            RecoveryClass::Invalid => continue,
                            RecoveryClass::Unverifiable
                            | RecoveryClass::Unsupported
                            | RecoveryClass::Unavailable => {
                                report.blocked_reason = Some(format!(
                                    "historical carrier head {candidate_id} is {}: {error:#}",
                                    class.name()
                                ));
                                return Ok(report);
                            }
                            RecoveryClass::Discontinuous | RecoveryClass::Valid => continue,
                        }
                    }
                };
                let candidate = candidate_chain
                    .first()
                    .context("validated candidate chain is empty")?;
                let candidate_in_floor = floor_chain.iter().any(|entry| entry.id == *candidate_id);
                if candidate.manifest.generation < floor_generation && candidate_in_floor {
                    replay_ids.insert(candidate_id.clone());
                    continue;
                }
                let floor_position = candidate_chain.iter().position(|entry| {
                    entry.id == floor_id && entry.manifest.generation == floor_generation
                });
                if floor_position.is_none() {
                    report.blocked_reason = Some(format!(
                        "authenticated historical head {candidate_id} does not descend from the pinned floor"
                    ));
                    return Ok(report);
                }
                descendants.push((
                    RecoveryCandidate {
                        manifest_id: candidate.id.clone(),
                        generation: candidate.manifest.generation,
                        outer_commit: Some(commit.commit_id.clone()),
                        verified_signer: candidate.verified_signer.clone(),
                    },
                    candidate_chain,
                ));
            }
            for (index, (left, left_chain)) in descendants.iter().enumerate() {
                for (right, right_chain) in descendants.iter().skip(index + 1) {
                    let left_is_ancestor =
                        right_chain.iter().any(|entry| entry.id == left.manifest_id);
                    let right_is_ancestor =
                        left_chain.iter().any(|entry| entry.id == right.manifest_id);
                    if !left_is_ancestor && !right_is_ancestor {
                        report.conflict = true;
                    }
                }
            }
        }
        if report.conflict {
            report.blocked_reason = Some(
                "authenticated descendants conflict; refusing to choose between forks".to_owned(),
            );
            report.candidates.push(floor_candidate);
            report
                .candidates
                .extend(descendants.into_iter().map(|(candidate, _)| candidate));
            report.replays = replay_ids.into_iter().collect();
            return Ok(report);
        }

        let mut offers = vec![(floor_candidate.clone(), floor_chain.clone())];
        offers.extend(descendants);
        offers.sort_by_key(|(candidate, _)| candidate.generation);
        report.candidates = offers
            .iter()
            .map(|(candidate, _)| candidate.clone())
            .collect();
        report.replays = replay_ids.into_iter().collect();
        let default_offer = offers.last().context("recovery floor offer is missing")?;
        report.default_base = Some(default_offer.0.manifest_id.clone());
        if !carrier_history {
            report.warning = Some(STALE_FLOOR_WARNING.to_owned());
        }
        if !options.publish {
            return Ok(report);
        }

        let selected_id = options.base.unwrap_or(&default_offer.0.manifest_id);
        let selected = match offers
            .iter()
            .find(|(candidate, _)| candidate.manifest_id == selected_id)
        {
            Some(selected) => selected,
            None => {
                report.blocked_reason = Some(format!(
                    "selected base {selected_id} is not an authenticated recovery offer"
                ));
                return Ok(report);
            }
        };
        if selected.0.generation < default_offer.0.generation && !options.discard_newer {
            report.blocked_reason = Some(format!(
                "choosing older base {} requires --discard-newer",
                selected.0.manifest_id
            ));
            return Ok(report);
        }
        if !carrier_history && !options.accept_stale_floor {
            report.blocked_reason = Some(format!(
                "directory recovery requires --accept-stale-floor. {}",
                STALE_FLOOR_WARNING
            ));
            return Ok(report);
        }
        let base_state = selected
            .1
            .first()
            .filter(|entry| entry.id == selected.0.manifest_id)
            .context("selected recovery base is missing from its validated chain")?;
        if !base_state.policy.is_active_writer(&self.key.device_id()?) {
            report.blocked_reason =
                Some("device is not an active writer under the selected base policy".to_owned());
            return Ok(report);
        }
        if let Err(error) = self.restore_base_objects(&selected.1) {
            report.blocked_reason = Some(format!("required ciphertext is unavailable: {error:#}"));
            return Ok(report);
        }
        if let Err(error) = self.verify_base_graph(&selected.1) {
            report.blocked_reason = Some(format!(
                "selected base does not resolve to a complete local object graph: {error:#}"
            ));
            return Ok(report);
        }
        let required_manifests: Vec<_> = selected.1.iter().map(|entry| entry.id.clone()).collect();
        let required_packs: Vec<_> = selected
            .1
            .iter()
            .flat_map(|entry| entry.manifest.new_packs.iter().map(|pack| pack.id.clone()))
            .collect();
        self.storage
            .prepare_recovery(&required_manifests, &required_packs)?;

        let next_key = random_key();
        let generation = base_state.manifest.generation + 1;
        let next = Manifest {
            format_version: base_state.manifest.format_version,
            repository_root: base_state.manifest.repository_root.clone(),
            generation,
            previous: Some(base_state.id.clone()),
            policy_id: base_state.policy.id.clone(),
            policy_generation: base_state.policy.body.generation,
            authorization: ManifestAuthorization::Writer,
            total_pack_count: base_state.manifest.total_pack_count,
            refs: base_state.manifest.refs.clone(),
            new_packs: Vec::new(),
            predecessor_key_wrap: Some(wrap_predecessor_key(
                &next_key,
                &base_state.generation_key,
                &base_state.manifest.repository_root,
                generation,
                &base_state.id,
            )?),
            introduced_policy: None,
        };
        let recovered_id = self.commit_manifest_with_observation(
            CommitHead {
                previous: Some(base_state),
                observation: Some(&observation),
            },
            &base_state.policy,
            None,
            &next_key,
            ManifestAuthorization::Writer,
            next.clone(),
        )?;
        self.pin_manifest_locked(&state_path, &recovered_id, &next)?;
        report.published_manifest = Some(recovered_id);
        report.blocked_reason = None;
        Ok(report)
    }

    fn claimed_signer_for_head(&self, head: &str) -> Result<String> {
        let (_, encrypted, header) = self.read_manifest_material(head)?;
        let key = unwrap_generation_key(&header, &self.key)?;
        Ok(open_manifest(&encrypted, &key)?.claimed_signer_id)
    }

    fn check_chain_ciphertext_presence(&self, chain: &[OpenedState]) -> Result<()> {
        for state in chain {
            for descriptor in &state.manifest.new_packs {
                self.storage
                    .open_object(ObjectKind::Pack, &descriptor.id)
                    .with_context(|| format!("required pack {} is unavailable", descriptor.id))?;
            }
        }
        Ok(())
    }

    fn restore_base_objects(&self, chain: &[OpenedState]) -> Result<()> {
        for state in chain {
            self.ensure_object_available(ObjectKind::Manifest, &state.id)?;
            for descriptor in &state.manifest.new_packs {
                self.ensure_object_available(ObjectKind::Pack, &descriptor.id)?;
            }
        }
        Ok(())
    }

    fn verify_base_graph(&self, chain: &[OpenedState]) -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let init = std::process::Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg("--quiet")
            .arg(temporary.path())
            .output()?;
        if !init.status.success() {
            bail!(
                "git init for recovery connectivity check failed: {}",
                String::from_utf8_lossy(&init.stderr).trim()
            )
        }
        for entry in chain.iter().rev() {
            for descriptor in &entry.manifest.new_packs {
                let encrypted = self.storage.open_object(ObjectKind::Pack, &descriptor.id)?;
                let pack_key = derive_subkey(
                    &entry.generation_key,
                    &entry.manifest.repository_root,
                    descriptor.generation,
                    SubkeyKind::Pack,
                    descriptor.ordinal,
                )?;
                let mut importer = git::start_pack_import(temporary.path())?;
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
            }
        }
        git::ensure_refs_connected_since(
            temporary.path(),
            &chain
                .first()
                .context("selected recovery chain is empty")?
                .manifest
                .refs,
            &BTreeMap::new(),
        )
    }

    fn ensure_object_available(&self, kind: ObjectKind, id: &str) -> Result<()> {
        if self.storage_object_matches(kind, id)? {
            return Ok(());
        }
        if self.storage.restore_historical_object(kind, id)?
            && self.storage_object_matches(kind, id)?
        {
            return Ok(());
        }
        bail!("required {:?} object {id} is missing or corrupt", kind)
    }

    fn storage_object_matches(&self, kind: ObjectKind, id: &str) -> Result<bool> {
        let mut reader = match self.storage.open_object(kind, id) {
            Ok(reader) => reader,
            Err(_) => return Ok(false),
        };
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()) == id)
    }

    fn current_chain(&self) -> Result<Vec<OpenedState>> {
        let _timer = trace::Span::new("manifest_chain_authentication");
        let head = self
            .storage
            .read_head()?
            .context("encrypted repository is not initialized")?;
        self.chain_from(&head, &mut |id| self.read_manifest_material(id), None)
    }

    fn chain_from<F>(
        &self,
        head: &str,
        read_material: &mut F,
        mut budget: Option<&mut RecoveryBudget>,
    ) -> Result<Vec<OpenedState>>
    where
        F: FnMut(&str) -> Result<(String, Vec<u8>, ManifestHeader)>,
    {
        let (mut id, mut encrypted, mut header) = read_material(head)?;
        if let Some(budget) = budget.as_deref_mut() {
            budget.charge_manifest(&header, encrypted.len())?;
        }
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
            let (parent_id, parent_encrypted, parent_header) = read_material(&previous_id)?;
            if let Some(budget) = budget.as_deref_mut() {
                budget.charge_manifest(&parent_header, parent_encrypted.len())?;
            }
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
            let verified_signer = opened.claimed_signer_id.clone();
            chain_oldest_first.push(OpenedState {
                id,
                manifest: opened.manifest,
                header: opened.header,
                policy,
                generation_key,
                verified_signer,
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
        self.commit_manifest_with_observation(
            CommitHead {
                previous,
                observation: None,
            },
            policy,
            parent_policy,
            generation_key,
            authorization,
            manifest,
        )
    }

    fn commit_manifest_with_observation(
        &self,
        head: CommitHead<'_>,
        policy: &PolicyState,
        parent_policy: Option<&PolicyState>,
        generation_key: &[u8; 32],
        authorization: ManifestAuthorization,
        manifest: Manifest,
    ) -> Result<String> {
        let manifest_timer = trace::Span::new("manifest_seal_and_self_verify");
        match head.previous {
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
        if let Some(previous) = head.previous {
            let recovered =
                unwrap_predecessor_key(generation_key, &opened.manifest, &previous.header)?;
            if *recovered != *previous.generation_key {
                bail!("new manifest predecessor link did not recover the parent key")
            }
        }
        if opened.header.generation != manifest.generation {
            bail!("new manifest self-check changed generation")
        }
        drop(manifest_timer);
        let cas_timer = trace::Span::new("manifest_compare_and_swap_publish");
        if let Some(observation) = head.observation {
            self.storage
                .compare_and_swap_observed_head(observation, &id)?;
        } else {
            self.storage
                .compare_and_swap_head(head.previous.map(|state| state.id.as_str()), &id)?;
        }
        drop(cas_timer);
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RejectedHeadEvidence {
    head_id: String,
    classification: RecoveryClass,
    reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RejectedHeadLog {
    format_version: u32,
    entries: Vec<RejectedHeadEvidence>,
}

fn classify_recovery_error(
    error: &anyhow::Error,
    raw_head: Option<&[u8]>,
) -> (RecoveryClass, String) {
    let detail = format!("{error:#}");
    if detail.contains("unsupported") || detail.contains("reserved but not implemented") {
        return (RecoveryClass::Unsupported, detail);
    }
    if detail.contains("device is not an active reader")
        || detail.contains("cannot open the generation key")
    {
        return (RecoveryClass::Unverifiable, detail);
    }
    if detail.contains("key file belongs to a different repository") {
        return (RecoveryClass::Discontinuous, detail);
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|source| source.kind() != io::ErrorKind::InvalidData)
    }) {
        return (RecoveryClass::Unavailable, detail);
    }
    if detail.contains("encrypted repository has no storage HEAD") && raw_head.is_none() {
        return (RecoveryClass::Unavailable, detail);
    }
    (RecoveryClass::Invalid, detail)
}

fn record_rejected_head(
    state_path: &Path,
    head_id: &str,
    classification: RecoveryClass,
    reason: &str,
) -> Result<()> {
    let directory = state_path
        .parent()
        .context("client state path has no parent")?;
    let path = directory.join("rejected-heads.json");
    let mut log = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<RejectedHeadLog>(&bytes).unwrap_or_default(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => RejectedHeadLog::default(),
        Err(error) => return Err(error.into()),
    };
    log.format_version = 1;
    log.entries.retain(|entry| entry.head_id != head_id);
    let reason: String = reason.chars().take(512).collect();
    log.entries.push(RejectedHeadEvidence {
        head_id: head_id.to_owned(),
        classification,
        reason,
    });
    if log.entries.len() > MAX_REJECTED_HEADS {
        let remove = log.entries.len() - MAX_REJECTED_HEADS;
        log.entries.drain(..remove);
    }
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = directory.join(format!(".rejected-heads-{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(&log)?)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    crate::persist::sync_directory(directory)?;
    Ok(())
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

fn write_client_state_locked(
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
    persist_client_state_locked(path, &state)
}

fn write_published_client_state_locked(
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
    persist_client_state_locked(path, &state)
}

fn persist_client_state_locked(path: &Path, state: &ClientState) -> Result<()> {
    let previous = read_client_state(path)?;
    let state = merge_client_state(previous, state.clone())?;
    persist_client_state(path, &state)
}

fn merge_client_state(previous: ClientState, mut next: ClientState) -> Result<ClientState> {
    if previous.format_version != 5 {
        return Ok(next);
    }
    if next.generation.is_some()
        && (next.head_id.is_none()
            || next.policy_generation.is_none()
            || next.repository_root.is_none())
    {
        bail!("client state update is missing a continuity pin field")
    }
    if let (Some(old_root), Some(new_root)) = (&previous.repository_root, &next.repository_root)
        && old_root != new_root
    {
        bail!("remote repository root changed")
    }
    if previous.generation.is_some() && next.generation.is_none() {
        return Ok(previous);
    }

    if let (Some(old_generation), Some(new_generation)) = (previous.generation, next.generation) {
        if old_generation > new_generation {
            return Ok(previous);
        }
        if old_generation == new_generation {
            if let (Some(old_id), Some(new_id)) = (&previous.head_id, &next.head_id)
                && old_id != new_id
            {
                bail!("remote manifest history forked from the locally pinned head")
            }
            if let (Some(old_policy), Some(new_policy)) =
                (previous.policy_generation, next.policy_generation)
                && old_policy != new_policy
            {
                bail!("remote policy pin changed within the same manifest generation")
            }
        }
    }
    if let (Some(old_policy), Some(new_policy)) =
        (previous.policy_generation, next.policy_generation)
        && new_policy < old_policy
    {
        bail!("remote policy rolled back")
    }

    if previous.repository_root.is_some() {
        next.repository_root = previous.repository_root.clone();
    }
    if next.head_id.is_none() {
        next.head_id = previous.head_id.clone();
    }
    if previous.policy_generation.is_some() {
        next.policy_generation = previous.policy_generation.max(next.policy_generation);
    }
    if previous
        .imported_generation
        .is_some_and(|old| next.imported_generation.is_none_or(|new| new < old))
    {
        next.imported_generation = previous.imported_generation;
        next.verified_refs = previous.verified_refs;
    }

    let mut packs = previous.packs;
    packs.extend(next.packs);
    packs.sort();
    packs.dedup();
    next.packs = packs;
    Ok(next)
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
    let _state_lock = ClientStateLock::acquire(path)?;
    persist_client_state_locked(path, &state)
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
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{ClientState, read_client_state, testing_write_client_state};

    #[test]
    fn concurrent_client_state_process_writes_never_lower_or_corrupt_the_floor() {
        let temporary = tempfile::tempdir().unwrap();
        let state_path = temporary.path().join("state.json");
        testing_write_client_state(&state_path, "head-10", 10).unwrap();
        let release = temporary.path().join("release-old-writer");
        let ready = temporary.path().join("old-writer-ready");
        let executable = env::current_exe().unwrap();

        let older = Command::new(&executable)
            .args([
                "--exact",
                "repository::tests::client_state_process_write_worker",
                "--nocapture",
            ])
            .env("E2EE_TEST_CLIENT_STATE_PATH", &state_path)
            .env("E2EE_TEST_CLIENT_STATE_GENERATION", "11")
            .env("E2EE_TEST_CLIENT_STATE_READY", &ready)
            .env("E2EE_TEST_CLIENT_STATE_RELEASE", &release)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "older writer did not reach its wait point");

        let newer = launch_client_state_writer(&executable, &state_path, 12);
        let newer_output = newer.wait_with_output().unwrap();
        assert!(
            newer_output.status.success(),
            "newer writer failed: {}",
            String::from_utf8_lossy(&newer_output.stderr)
        );
        fs::write(&release, "continue").unwrap();

        let older_output = older.wait_with_output().unwrap();
        assert!(
            older_output.status.success(),
            "older writer failed: {}",
            String::from_utf8_lossy(&older_output.stderr)
        );
        let state = read_client_state(&state_path).unwrap();
        assert_eq!(state.generation, Some(12));
        assert_eq!(state.head_id.as_deref(), Some("head-12"));
    }

    #[test]
    fn client_state_process_write_worker() {
        let Ok(path) = env::var("E2EE_TEST_CLIENT_STATE_PATH") else {
            return;
        };
        let generation = env::var("E2EE_TEST_CLIENT_STATE_GENERATION")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        if let (Ok(ready), Ok(release)) = (
            env::var("E2EE_TEST_CLIENT_STATE_READY"),
            env::var("E2EE_TEST_CLIENT_STATE_RELEASE"),
        ) {
            fs::write(&ready, "ready").unwrap();
            let release = Path::new(&release);
            let deadline = Instant::now() + Duration::from_secs(10);
            while !release.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(release.exists(), "parent did not release the older writer");
        }
        testing_write_client_state(Path::new(&path), &format!("head-{generation}"), generation)
            .unwrap();
    }

    fn launch_client_state_writer(executable: &Path, state_path: &Path, generation: u64) -> Child {
        Command::new(executable)
            .args([
                "--exact",
                "repository::tests::client_state_process_write_worker",
                "--nocapture",
            ])
            .env("E2EE_TEST_CLIENT_STATE_PATH", state_path)
            .env("E2EE_TEST_CLIENT_STATE_GENERATION", generation.to_string())
            .spawn()
            .unwrap()
    }

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
