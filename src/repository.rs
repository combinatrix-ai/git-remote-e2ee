use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::continuity::{ContinuityFloor, FileLock, FloorGuard, read_json, write_json};
use crate::crypto::{
    KeyFile, PublicDevice, SecretKey, SubkeyKind, derive_subkey, object_id, open_pack_stream,
    random_key, seal_pack_stream,
};
use crate::error::{
    BudgetExhausted, ForeignRepository, InvalidState, MissingStorageHead, NotActiveReader,
    ObjectUnavailable, Unsupported,
};
use crate::git;
use crate::gitcmd::{self, GitRepository};
use crate::manifest::{
    Manifest, ManifestAuthorization, ManifestHeader, OpenedManifest, PackDescriptor, open_manifest,
    pack_aad, peek_manifest_header, seal_manifest, unwrap_generation_key, unwrap_predecessor_key,
    verify_manifest, wrap_predecessor_key,
};
use crate::policy::{DeviceRecord, DeviceRoles, PolicyState};
use crate::storage::{HeadObservation, ObjectKind, Storage, StorageOccupied, StoredHead};
use crate::trace;

const MAX_RECOVERY_OUTER_COMMITS: usize = 2048;
const MAX_RECOVERY_CANDIDATES: usize = 256;
const MAX_RECOVERY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECOVERY_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECOVERY_CRYPTO_OPERATIONS: u64 = 1_000_000;
const MAX_REJECTED_HEADS: usize = 16;
const STALE_FLOOR_WARNING: &str = "Updates after this floor may be omitted. This may also omit revocations and disclose subsequently published content to devices excluded by a newer policy.";

#[derive(Debug, thiserror::Error)]
pub enum PushRejection {
    #[error("non-fast-forward update rejected for {0}")]
    NonFastForward(String),
    #[error("remote tip for {0} is missing locally; fetch first")]
    FetchFirst(String),
    #[error("tag {0} already exists; use --force to move it")]
    AlreadyExists(String),
}

impl PushRejection {
    /// The status text Git's transport layer recognizes in a remote-helper
    /// `error <ref> <status>` line, which turns the result into an ordinary
    /// `[rejected]` entry with Git's own advice.
    pub fn git_status(&self) -> &'static str {
        match self {
            Self::NonFastForward(_) => "non-fast forward",
            Self::FetchFirst(_) => "fetch first",
            Self::AlreadyExists(_) => "already exists",
        }
    }
}

/// Where [`EncryptedRepository::initialize`] stopped.
#[derive(Debug, thiserror::Error)]
pub enum InitializeError {
    /// The genesis compare-and-swap was not attempted, or storage refused it
    /// as [`StorageOccupied`] before writing. Storage has no head from this
    /// call.
    #[error(transparent)]
    BeforePublication(anyhow::Error),
    /// The genesis compare-and-swap returned an error. It may have landed.
    #[error("storage may already be initialized: genesis publication reported an error")]
    PublicationUncertain(#[source] anyhow::Error),
    /// The genesis head is published. Pinning it on this machine failed.
    #[error("storage is initialized with genesis {id}, but pinning it on this machine failed")]
    AfterPublication {
        id: String,
        #[source]
        error: anyhow::Error,
    },
}

/// The device may read but not publish.
#[derive(Debug, thiserror::Error)]
#[error("this device is read-only; ask an administrator for the write role")]
pub struct ReadOnlyDevice;

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

/// This checkout's import progress for one repository root. It records work
/// already done here; continuity is the machine floor's job.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutProgress {
    format_version: u32,
    // The last generation whose pack deltas and advertised refs we imported and checked.
    imported_generation: Option<u64>,
    verified_refs: BTreeMap<String, String>,
}

const CHECKOUT_PROGRESS_FORMAT: u32 = 2;

/// A locked view of `.git/git-remote-e2ee/<root>/` in one checkout. Always
/// acquired after the machine floor.
struct Checkout {
    directory: PathBuf,
    _lock: FileLock,
}

impl Checkout {
    fn progress_path(&self) -> PathBuf {
        self.directory.join("progress.json")
    }

    fn read(&self) -> Result<CheckoutProgress> {
        let Some(progress) = read_json::<CheckoutProgress>(&self.progress_path())? else {
            return Ok(CheckoutProgress::default());
        };
        if progress.format_version != CHECKOUT_PROGRESS_FORMAT {
            bail!(
                "unsupported checkout progress format {}",
                progress.format_version
            )
        }
        Ok(progress)
    }

    fn write(&self, mut progress: CheckoutProgress) -> Result<()> {
        progress.format_version = CHECKOUT_PROGRESS_FORMAT;
        write_json(&self.progress_path(), &progress)
    }
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

/// What a push does to one destination ref.
#[derive(Clone, Copy, Debug)]
pub enum RefChange<'a> {
    Update { source: &'a str, force: bool },
    Delete,
}

/// One `push` line of a remote-helper batch.
#[derive(Clone, Copy, Debug)]
pub struct RefPush<'a> {
    pub destination: &'a str,
    pub change: RefChange<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushMode {
    Publish,
    /// Runs every check without publishing (`git push --dry-run`).
    DryRun,
}

#[derive(Debug)]
pub enum RefOutcome {
    /// Passed preflight; its result is the batch's publication result.
    Accepted,
    Rejected(anyhow::Error),
}

#[derive(Debug)]
pub struct PushOutcome {
    /// One outcome per requested change, in request order.
    pub refs: Vec<RefOutcome>,
    /// The head manifest ID after the batch: the published successor, or the
    /// current head when nothing needed publishing. Its error fails every
    /// accepted ref.
    pub publication: Result<String>,
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
            bail!(BudgetExhausted(
                "recovery manifest byte budget exhausted".to_owned()
            ))
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
            bail!(BudgetExhausted(
                "recovery cryptographic-operation budget exhausted".to_owned()
            ))
        }
        Ok(())
    }
}

pub struct EncryptedRepository<S> {
    storage: S,
    key: KeyFile,
    state_dir: PathBuf,
}

impl<S: Storage> EncryptedRepository<S> {
    /// `state_dir` holds this machine's continuity floors, one per repository
    /// root; binaries pass `continuity::default_state_dir()`.
    pub fn new(storage: S, key: KeyFile, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            storage,
            key,
            state_dir: state_dir.into(),
        }
    }

    fn lock_floor(&self) -> Result<FloorGuard> {
        FloorGuard::acquire(&self.state_dir, &self.key.repository_root)
    }

    /// Continuity progress is keyed by repository root rather than by Git
    /// remote name, so `git remote rename` or a second remote for the same
    /// encrypted repository shares it.
    fn open_checkout(&self, repo: &GitRepository) -> Result<Checkout> {
        let directory = repo
            .git_dir()
            .join("git-remote-e2ee")
            .join(&self.key.repository_root);
        crate::persist::create_dir_all_durable(&directory)
            .with_context(|| format!("create {}", directory.display()))?;
        let lock = FileLock::acquire(&directory.join("progress.json"))?;
        Ok(Checkout {
            directory,
            _lock: lock,
        })
    }

    /// Authenticates the storage chain and requires it to pass through the
    /// machine floor. Another process on this machine may have advanced the
    /// floor after this storage view was opened, so a view that fails the
    /// floor is refreshed once before the failure counts as a rollback.
    fn pinned_chain(&self, floor: &FloorGuard) -> Result<Vec<OpenedState>> {
        let floor = floor.read()?;
        let chain = self.current_chain()?;
        match validate_pinned_head(&chain, floor.as_ref()) {
            Ok(()) => Ok(chain),
            Err(error) if !self.storage.refresh()? => Err(error),
            Err(_) => {
                let chain = self.current_chain()?;
                validate_pinned_head(&chain, floor.as_ref())?;
                Ok(chain)
            }
        }
    }

    /// Publishes the genesis head and pins it on this machine. The error says
    /// whether the genesis compare-and-swap was attempted, so a caller knows
    /// whether a key it created for this call may still be discarded.
    pub fn initialize(&self, owner_label: &str) -> Result<String, InitializeError> {
        let (floor, genesis, id) = self
            .prepare_genesis(owner_label)
            .map_err(InitializeError::BeforePublication)?;
        self.storage
            .compare_and_swap_head(None, &id)
            .map_err(|error| {
                if error.downcast_ref::<StorageOccupied>().is_some() {
                    InitializeError::BeforePublication(error)
                } else {
                    InitializeError::PublicationUncertain(error)
                }
            })?;
        floor
            .advance(ContinuityFloor::at(&id, &genesis))
            .map_err(|error| InitializeError::AfterPublication {
                id: id.clone(),
                error,
            })?;
        Ok(id)
    }

    fn prepare_genesis(&self, owner_label: &str) -> Result<(FloorGuard, Manifest, String)> {
        let floor = self.lock_floor()?;
        if self.storage.read_head()?.is_some() {
            bail!("encrypted repository is already initialized")
        }
        if floor.read()?.is_some() {
            bail!(
                "this machine already pins repository root {}; refusing to initialize other storage for it",
                self.key.repository_root
            )
        }
        let (policy, policy_bytes) = PolicyState::genesis(&self.key, owner_label)?;
        let generation_key = random_key();
        let genesis = Manifest::genesis(self.key.repository_root.clone(), &policy, policy_bytes);
        let id = self.seal_and_store_manifest(
            None,
            &policy,
            None,
            &generation_key,
            ManifestAuthorization::PolicyTransition,
            genesis.clone(),
        )?;
        Ok((floor, genesis, id))
    }

    pub fn add_device(
        &self,
        public: PublicDevice,
        label: &str,
        roles: DeviceRoles,
    ) -> Result<(String, String)> {
        self.change_policy(|current| {
            if current.policy.device(&public.device_id).is_some() {
                bail!("device already exists in policy")
            }
            let mut devices = current.policy.body.devices.clone();
            devices.push(DeviceRecord {
                public,
                label: label.to_owned(),
                roles,
                revoked_at: None,
            });
            Ok(devices)
        })
    }

    pub fn revoke_device(&self, device_id: &str) -> Result<(String, String)> {
        self.change_policy(|current| {
            let mut devices = current.policy.body.devices.clone();
            let target = devices
                .iter_mut()
                .find(|device| device.public.device_id == device_id && device.active())
                .context("device is not active in the current policy")?;
            target.revoked_at = Some(
                current
                    .policy
                    .body
                    .generation
                    .checked_add(1)
                    .context("policy generation overflow")?,
            );
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
            Ok(devices)
        })
    }

    fn change_policy(
        &self,
        next_devices: impl FnOnce(&OpenedState) -> Result<Vec<DeviceRecord>>,
    ) -> Result<(String, String)> {
        let floor = self.lock_floor()?;
        let chain = self.pinned_chain(&floor)?;
        let current = chain.first().context("manifest chain is empty")?;
        self.require_admin(&current.policy)?;
        let devices = next_devices(current)?;
        let (next_policy, policy_bytes) =
            PolicyState::successor(&current.policy, devices, &self.key)?;
        let next_key = random_key();
        let next = transition_manifest(current, &next_policy, policy_bytes, &next_key)?;
        next_policy.validate_successor(&current.policy)?;
        let manifest_id = self.commit_manifest(
            Some(current),
            &next_policy,
            Some(&current.policy),
            &next_key,
            ManifestAuthorization::PolicyTransition,
            next.clone(),
        )?;
        floor.advance(ContinuityFloor::at(&manifest_id, &next))?;
        Ok((manifest_id, next_policy.id))
    }

    /// Returns the current membership only after the head passes the machine
    /// floor, so storage cannot hide a revocation by serving an older,
    /// validly signed policy.
    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        Ok(self.pinned_head()?.policy.body.devices)
    }

    /// The authenticated storage head, after it passes the machine floor.
    pub fn current_manifest(&self) -> Result<(String, Manifest)> {
        let head = self.pinned_head()?;
        Ok((head.id, head.manifest))
    }

    fn pinned_head(&self) -> Result<OpenedState> {
        let floor = self.lock_floor()?;
        let current = self
            .pinned_chain(&floor)?
            .into_iter()
            .next()
            .context("manifest chain is empty")?;
        floor.advance(ContinuityFloor::at(&current.id, &current.manifest))?;
        Ok(current)
    }

    fn require_admin(&self, policy: &PolicyState) -> Result<()> {
        if !policy.is_active_admin(&self.key.device_id()?) {
            bail!("device is not an active administrator")
        }
        Ok(())
    }

    /// Preflights every change of one helper push batch against the same
    /// pinned head and publishes the accepted ones as at most one successor
    /// generation with at most one pack. An `Err` means no change was checked
    /// (for example, a read-only device), so it applies to every ref.
    pub fn push(
        &self,
        repo: &GitRepository,
        pushes: &[RefPush<'_>],
        mode: PushMode,
    ) -> Result<PushOutcome> {
        let floor = self.lock_floor()?;
        let current = self
            .pinned_chain(&floor)?
            .into_iter()
            .next()
            .context("manifest chain is empty")?;
        let device_id = self.key.device_id()?;
        if !current.policy.is_active_writer(&device_id) {
            if current.policy.is_active_reader(&device_id) {
                bail!(ReadOnlyDevice)
            }
            bail!("device is not an active writer")
        }
        git::validate_inner_refs(&current.manifest.refs)?;

        let mut objects = git::Objects::new(repo);
        let mut destinations = BTreeSet::new();
        let mut next_refs = current.manifest.refs.clone();
        let mut pack_refs = BTreeMap::new();
        let mut refs = Vec::with_capacity(pushes.len());
        for push in pushes {
            let destination = push.destination;
            let preflight = if destinations.insert(destination) {
                preflight_ref_change(repo, &mut objects, &current.manifest.refs, push)
            } else {
                Err(anyhow::anyhow!(
                    "{destination} appears more than once in one push"
                ))
            };
            refs.push(match preflight {
                Ok(Some(next_object)) => {
                    if current.manifest.refs.get(destination) != Some(&next_object) {
                        pack_refs.insert(destination.to_owned(), next_object.clone());
                    }
                    next_refs.insert(destination.to_owned(), next_object);
                    RefOutcome::Accepted
                }
                Ok(None) => {
                    next_refs.remove(destination);
                    RefOutcome::Accepted
                }
                Err(error) => RefOutcome::Rejected(error),
            });
        }

        let publication = if mode == PushMode::DryRun || next_refs == current.manifest.refs {
            floor.advance(ContinuityFloor::at(&current.id, &current.manifest))?;
            Ok(current.id.clone())
        } else {
            self.publish_refs(repo, &mut objects, &floor, &current, next_refs, &pack_refs)
        };
        Ok(PushOutcome { refs, publication })
    }

    fn publish_refs(
        &self,
        repo: &GitRepository,
        objects: &mut git::Objects<'_>,
        floor: &FloorGuard,
        current: &OpenedState,
        next_refs: BTreeMap<String, String>,
        pack_refs: &BTreeMap<String, String>,
    ) -> Result<String> {
        let next_key = random_key();
        let generation = current
            .manifest
            .generation
            .checked_add(1)
            .context("manifest generation overflow")?;
        let mut new_packs = Vec::new();
        let mut total_pack_count = current.manifest.total_pack_count;
        if !pack_refs.is_empty() {
            // Every reader that accepted the parent holds the complete graphs
            // of its refs, so even a forced update need not resend them.
            let mut exclusions = BTreeMap::new();
            for (reference, object) in &current.manifest.refs {
                if objects.exists(object)? {
                    exclusions.insert(reference.clone(), object.clone());
                }
            }
            let ordinal = 0;
            let pack_key = derive_subkey(
                &next_key,
                &current.manifest.repository_root,
                generation,
                SubkeyKind::Pack,
                ordinal,
            )?;
            let pack_timer = trace::Span::new("inner_pack_encrypt_and_store");
            let mut pack_source = git::start_incremental_pack(repo, pack_refs, &exclusions)?;
            let mut pack_stage = self.storage.begin_object(ObjectKind::Pack)?;
            let sealed = seal_pack_stream(
                &pack_key,
                &mut pack_source,
                &mut pack_stage,
                &pack_aad(&current.manifest.repository_root, generation, ordinal),
            )?;
            pack_source.finish()?;
            let stage_finish_timer = trace::Span::new("inner_pack_stage_finish");
            pack_stage.finish(&sealed.object_id)?;
            drop(stage_finish_timer);
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
            Some(current),
            &current.policy,
            None,
            &next_key,
            ManifestAuthorization::Writer,
            next.clone(),
        )?;
        floor.advance(ContinuityFloor::at(&next_id, &next))?;
        let checkout = self.open_checkout(repo)?;
        let mut progress = checkout.read()?;
        if progress.verified_refs == current.manifest.refs && git::has_complete_object_graph(repo) {
            // The completed local pack walk covers new reachability only beyond
            // refs already verified by this checkout. Shallow and promisor repos
            // can omit history, so they must not advance this frontier.
            progress.verified_refs = next.refs;
            checkout.write(progress)?;
        }
        Ok(next_id)
    }

    /// Imports the current generation and points `refs/remotes/<remote_name>/*`
    /// and tags at its refs, as `git fetch` through the helper would.
    pub fn fetch_into(&self, repo: &GitRepository, remote_name: &str) -> Result<Manifest> {
        let manifest = self.import_packs(repo)?;
        for (reference, object) in &manifest.refs {
            match git::InnerRefKind::of(reference)? {
                git::InnerRefKind::Branch => {
                    let short = reference.strip_prefix("refs/heads/").unwrap();
                    git::update_ref(repo, &format!("refs/remotes/{remote_name}/{short}"), object)?;
                }
                git::InnerRefKind::Tag => git::update_ref(repo, reference, object)?,
            }
        }
        Ok(manifest)
    }

    pub fn observe_manifest(&self, repo: &GitRepository) -> Result<Manifest> {
        let floor = self.lock_floor()?;
        let checkout = self.open_checkout(repo)?;
        let chain = self.pinned_chain(&floor)?;
        let current = chain.first().context("manifest chain is empty")?;
        git::validate_inner_refs(&current.manifest.refs)?;
        floor.advance(ContinuityFloor::at(&current.id, &current.manifest))?;
        // Git skips the helper's fetch command when every advertised object is
        // already local, for example after a membership change, a deletion, or
        // a tag that points at an existing object. Record the import here only
        // when the advertised refs are fully connected locally, which is the
        // same check a fetch would finish with. Earlier packs are not needed
        // once these refs are connected, because later packs are built
        // against these tips.
        let mut progress = checkout.read()?;
        if git::ensure_refs_connected_since(repo, &current.manifest.refs, &progress.verified_refs)
            .is_ok()
        {
            progress.imported_generation = Some(current.manifest.generation);
            progress.verified_refs = current.manifest.refs.clone();
            checkout.write(progress)?;
        }
        Ok(current.manifest.clone())
    }

    pub fn import_packs(&self, repo: &GitRepository) -> Result<Manifest> {
        let floor = self.lock_floor()?;
        let checkout = self.open_checkout(repo)?;
        let chain = self.pinned_chain(&floor)?;
        let current = chain.first().context("manifest chain is empty")?;
        git::validate_inner_refs(&current.manifest.refs)?;
        let progress = checkout.read()?;
        self.import_chain_packs(repo, &chain, progress.imported_generation)?;
        let connectivity_timer = trace::Span::new("inner_ref_connectivity_check");
        if git::ensure_refs_connected_since(repo, &current.manifest.refs, &progress.verified_refs)
            .is_err()
        {
            // Recorded progress is cache state, not proof that its objects
            // are still local: deleting a remote-tracking ref and pruning
            // removes them. Re-import the whole authenticated chain and check
            // the full graph; recorded progress is unchanged until that passes.
            self.import_chain_packs(repo, &chain, None)?;
            git::ensure_refs_connected_since(repo, &current.manifest.refs, &BTreeMap::new())?;
        }
        drop(connectivity_timer);
        floor.advance(ContinuityFloor::at(&current.id, &current.manifest))?;
        checkout.write(CheckoutProgress {
            format_version: CHECKOUT_PROGRESS_FORMAT,
            imported_generation: Some(current.manifest.generation),
            verified_refs: current.manifest.refs.clone(),
        })?;
        Ok(current.manifest.clone())
    }

    /// Imports, oldest first, the packs of every chain entry newer than
    /// `after_generation`. Chain authentication already rejects a pack ID
    /// that repeats anywhere in the chain.
    fn import_chain_packs(
        &self,
        repo: &GitRepository,
        chain: &[OpenedState],
        after_generation: Option<u64>,
    ) -> Result<()> {
        for entry in chain.iter().rev() {
            if after_generation.is_some_and(|generation| entry.manifest.generation <= generation) {
                continue;
            }
            for descriptor in &entry.manifest.new_packs {
                let mut importer = git::start_pack_import(repo)?;
                let decrypt_timer = trace::Span::new("pack_decrypt_to_index_pack");
                self.open_chain_pack(entry, descriptor, &mut importer)?;
                drop(decrypt_timer);
                importer.finish()?;
            }
        }
        Ok(())
    }

    /// Decrypts one pack of an authenticated chain entry into `plaintext`.
    /// Success proves the ciphertext is the one the manifest names; only Git
    /// can say whether the plaintext is a valid pack.
    fn open_chain_pack(
        &self,
        entry: &OpenedState,
        descriptor: &PackDescriptor,
        plaintext: impl io::Write,
    ) -> Result<()> {
        let encrypted = self.storage.open_object(ObjectKind::Pack, &descriptor.id)?;
        let pack_key = derive_subkey(
            &entry.generation_key,
            &entry.manifest.repository_root,
            descriptor.generation,
            SubkeyKind::Pack,
            descriptor.ordinal,
        )?;
        open_pack_stream(
            &pack_key,
            encrypted,
            plaintext,
            &pack_aad(
                &entry.manifest.repository_root,
                descriptor.generation,
                descriptor.ordinal,
            ),
            descriptor.plaintext_size,
            &descriptor.id,
        )?;
        Ok(())
    }

    /// Checks the whole manifest chain against the machine floor and
    /// authenticates every pack's ciphertext. It never hands plaintext to
    /// Git, so it does not prove the packs are valid Git packs.
    pub fn verify_ciphertext(&self) -> Result<Manifest> {
        let floor = self.lock_floor()?;
        let chain = self.pinned_chain(&floor)?;
        let current = chain.first().context("manifest chain is empty")?;
        let mut count = 0_u64;
        for entry in chain.iter().rev() {
            for descriptor in &entry.manifest.new_packs {
                self.open_chain_pack(entry, descriptor, io::sink())?;
                count += 1;
            }
        }
        if count != current.manifest.total_pack_count {
            bail!("manifest delta log pack count mismatch")
        }
        floor.advance(ContinuityFloor::at(&current.id, &current.manifest))?;
        Ok(current.manifest.clone())
    }

    pub fn recover(
        &self,
        repo: &GitRepository,
        options: RecoveryOptions<'_>,
    ) -> Result<RecoveryReport> {
        let floor_guard = self.lock_floor()?;
        let checkout = self.open_checkout(repo)?;
        let local_floor = floor_guard.read()?;
        let mut report = RecoveryReport {
            classification: RecoveryClass::Unavailable,
            reason: "could not read the storage head".to_owned(),
            head_id: None,
            claimed_signer: None,
            floor_id: local_floor.as_ref().map(|floor| floor.head_id.clone()),
            floor_generation: local_floor.as_ref().map(|floor| floor.generation),
            candidates: Vec::new(),
            default_base: None,
            replays: Vec::new(),
            conflict: false,
            freshness_unverified: local_floor.is_none(),
            warning: None,
            blocked_reason: None,
            published_manifest: None,
        };
        let observation = match self.storage.observe_head() {
            Ok(observation) => observation,
            Err(error) => {
                if error.is::<BudgetExhausted>() {
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
            None => match &observation.head {
                Some(head) => {
                    Err(proven_invalid(head.parse().err().unwrap_or_else(|| {
                        anyhow::anyhow!("storage HEAD is not a valid head")
                    })))
                }
                None => Err(MissingStorageHead.into()),
            },
        };
        match current_chain {
            Ok(chain) => {
                report.claimed_signer = chain.first().map(|entry| entry.verified_signer.clone());
                if local_floor.is_some() {
                    match validate_pinned_head(&chain, local_floor.as_ref()) {
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
                if error.is::<BudgetExhausted>() {
                    return Err(error).context("bounded recovery discovery failed");
                }
                let (class, reason) = classify_recovery_error(&error);
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
                    observation
                        .head
                        .as_ref()
                        .map(StoredHead::evidence)
                        .unwrap_or_default(),
                ))
            });
            record_rejected_head(
                &checkout,
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

        let Some(pinned) = local_floor.as_ref() else {
            report.freshness_unverified = true;
            report.blocked_reason = Some(
                "this repository has no authenticated continuity floor; freshness and fork identity are unverified".to_owned(),
            );
            return Ok(report);
        };

        let floor_id = pinned.head_id.as_str();
        let floor_generation = pinned.generation;
        let history = self
            .storage
            .recovery_history(MAX_RECOVERY_OUTER_COMMITS, MAX_RECOVERY_MANIFEST_BYTES)?;
        let carrier_history = history.is_some();
        let history = history.unwrap_or_default();
        if history.commits.len() > MAX_RECOVERY_OUTER_COMMITS {
            bail!(BudgetExhausted(
                "recovery outer-commit budget exhausted".to_owned()
            ))
        }
        let historical_bytes = history.manifests.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(bytes.len() as u64)
                .context("recovery manifest byte budget overflow")
        })?;
        if historical_bytes > MAX_RECOVERY_MANIFEST_BYTES {
            bail!(BudgetExhausted(
                "recovery manifest byte budget exhausted".to_owned()
            ))
        }
        budget.bytes_read = budget
            .bytes_read
            .checked_add(historical_bytes)
            .context("recovery manifest byte budget overflow")?;
        if budget.bytes_read > MAX_RECOVERY_BYTES {
            bail!(BudgetExhausted(
                "recovery manifest byte budget exhausted".to_owned()
            ))
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
                    let Some(bytes) = history.manifests.get(id) else {
                        return Err(current_error.context(format!(
                            "historical manifest {id} is not in carrier history"
                        )));
                    };
                    if object_id(bytes) != id {
                        return Err(proven_invalid(anyhow::anyhow!(
                            "historical manifest {id} content ID mismatch"
                        )));
                    }
                    let header = peek_manifest_header(bytes).map_err(proven_invalid)?;
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
            Err(error) if error.is::<BudgetExhausted>() => {
                return Err(error).context("bounded recovery discovery failed");
            }
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
                    "continuity floor does not match its authenticated manifest generation"
                        .to_owned(),
                );
                return Ok(report);
            }
        };
        if pinned.repository_root != floor.manifest.repository_root
            || pinned.policy_generation > floor.manifest.policy_generation
        {
            report.blocked_reason =
                Some("continuity floor metadata does not match the authenticated floor".to_owned());
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
                bail!(BudgetExhausted(
                    "recovery candidate budget exhausted".to_owned()
                ))
            }
            for (candidate_id, commit) in unique_heads {
                if candidate_id == floor_id {
                    continue;
                }
                // Membership needs no key: a device added after genesis cannot
                // open the heads that predate it, but they are in its floor chain.
                if floor_chain.iter().any(|entry| entry.id == *candidate_id) {
                    replay_ids.insert(candidate_id.clone());
                    continue;
                }
                let candidate_chain = match self.chain_from(
                    candidate_id,
                    &mut |id| read_history_material(id),
                    Some(&mut budget),
                ) {
                    Ok(chain) => chain,
                    Err(error) if error.is::<BudgetExhausted>() => {
                        return Err(error).context("bounded recovery discovery failed");
                    }
                    Err(error) => match classify_recovery_error(&error).0 {
                        RecoveryClass::Invalid => continue,
                        class => {
                            report.blocked_reason = Some(format!(
                                "historical carrier head {candidate_id} is {}: {error:#}",
                                class.name()
                            ));
                            return Ok(report);
                        }
                    },
                };
                let candidate = candidate_chain
                    .first()
                    .context("validated candidate chain is empty")?;
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
        floor_guard.advance(ContinuityFloor::at(&recovered_id, &next))?;
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
        let init = gitcmd::without_repository()
            .args(["init", "--bare", "--quiet"])
            .arg(temporary.path())
            .output()?;
        if !init.status.success() {
            bail!(
                "git init for recovery connectivity check failed: {}",
                String::from_utf8_lossy(&init.stderr).trim()
            )
        }
        let scratch = GitRepository::owned_git_dir(temporary.path());
        for entry in chain.iter().rev() {
            for descriptor in &entry.manifest.new_packs {
                let mut importer = git::start_pack_import(&scratch)?;
                self.open_chain_pack(entry, descriptor, &mut importer)?;
                importer.finish()?;
            }
        }
        let refs = &chain
            .first()
            .context("selected recovery chain is empty")?
            .manifest
            .refs;
        git::validate_inner_refs(refs)?;
        git::ensure_refs_connected_since(&scratch, refs, &BTreeMap::new())
    }

    fn ensure_object_available(&self, kind: ObjectKind, id: &str) -> Result<()> {
        if self.storage_object_matches(kind, id)? {
            return Ok(());
        }
        // Room for one corrupt maximal copy before the valid one.
        let restore_budget = kind.max_bytes().saturating_mul(2);
        if self
            .storage
            .restore_historical_object(kind, id, restore_budget)?
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
        let mut opened = open_manifest(&encrypted, &generation_key).map_err(proven_invalid)?;
        let mut unverified = Vec::new();
        let mut seen = HashSet::new();

        loop {
            if !seen.insert(id.clone()) {
                return Err(proven_invalid(anyhow::anyhow!(
                    "manifest chain contains a cycle"
                )));
            }
            let Some(previous_id) = opened.manifest.previous.clone() else {
                if opened.manifest.generation != 0 {
                    return Err(proven_invalid(anyhow::anyhow!(
                        "manifest chain terminated above generation zero"
                    )));
                }
                unverified.push((id, opened, generation_key));
                break;
            };
            let (parent_id, parent_encrypted, parent_header) = read_material(&previous_id)?;
            if let Some(budget) = budget.as_deref_mut() {
                budget.charge_manifest(&parent_header, parent_encrypted.len())?;
            }
            let parent_key =
                unwrap_predecessor_key(&generation_key, &opened.manifest, &parent_header)
                    .map_err(proven_invalid)?;
            unverified.push((id, opened, generation_key));
            id = parent_id;
            encrypted = parent_encrypted;
            header = parent_header;
            generation_key = parent_key;
            opened = open_manifest(&encrypted, &generation_key).map_err(proven_invalid)?;
            if opened.header != header {
                return Err(proven_invalid(anyhow::anyhow!(
                    "predecessor manifest header changed while opening"
                )));
            }
        }
        self.verify_opened_chain(unverified).map_err(proven_invalid)
    }

    /// Authenticates opened manifests oldest first against their policies.
    /// Every failure here is a property of authenticated bytes.
    fn verify_opened_chain(
        &self,
        unverified: Vec<(String, OpenedManifest, SecretKey)>,
    ) -> Result<Vec<OpenedState>> {
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
                        bail!(Unsupported(
                            "checkpoint transitions are reserved but not implemented".to_owned()
                        ))
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
            return Err(proven_invalid(anyhow::anyhow!(
                "manifest ciphertext hash mismatch"
            )));
        }
        let header = peek_manifest_header(&bytes).map_err(proven_invalid)?;
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
        let id = self.seal_and_store_manifest(
            head.previous,
            policy,
            parent_policy,
            generation_key,
            authorization,
            manifest,
        )?;
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

    /// Seals `manifest`, stores it as an object, and checks that it opens.
    /// No head moves.
    fn seal_and_store_manifest(
        &self,
        previous: Option<&OpenedState>,
        policy: &PolicyState,
        parent_policy: Option<&PolicyState>,
        generation_key: &[u8; 32],
        authorization: ManifestAuthorization,
        manifest: Manifest,
    ) -> Result<String> {
        let _manifest_timer = trace::Span::new("manifest_seal_and_self_verify");
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
        Ok(id)
    }
}

/// Checks one ref change against the parent's refs and returns the object the
/// destination will point at, or `None` for a deletion.
fn preflight_ref_change(
    repo: &GitRepository,
    objects: &mut git::Objects<'_>,
    parent_refs: &BTreeMap<String, String>,
    push: &RefPush<'_>,
) -> Result<Option<String>> {
    let destination_ref = push.destination;
    let ref_kind = git::validate_inner_ref(destination_ref)?;
    let old_object = parent_refs.get(destination_ref);
    let RefChange::Update { source, force } = push.change else {
        if old_object.is_none() {
            bail!("remote ref {destination_ref} does not exist")
        }
        if destination_ref == "refs/heads/main" {
            bail!(
                "cannot delete refs/heads/main because it is advertised as the remote default branch"
            )
        }
        return Ok(None);
    };

    let next_object = git::resolve_ref(repo, source)?;
    if old_object == Some(&next_object) {
        return Ok(Some(next_object));
    }
    if ref_kind == git::InnerRefKind::Branch {
        git::ensure_branch_target(objects, destination_ref, &next_object)?;
    }
    if ref_kind == git::InnerRefKind::Tag && old_object.is_some() && !force {
        return Err(PushRejection::AlreadyExists(destination_ref.to_owned()).into());
    }
    if ref_kind == git::InnerRefKind::Branch
        && let Some(old_object) = old_object
    {
        if !objects.exists(old_object)? {
            return Err(PushRejection::FetchFirst(destination_ref.to_owned()).into());
        }
        if !force && !git::is_ancestor(repo, old_object, &next_object)? {
            return Err(PushRejection::NonFastForward(destination_ref.to_owned()).into());
        }
    }
    Ok(Some(next_object))
}

fn transition_manifest(
    current: &OpenedState,
    policy: &PolicyState,
    policy_bytes: Vec<u8>,
    generation_key: &[u8; 32],
) -> Result<Manifest> {
    let generation = current
        .manifest
        .generation
        .checked_add(1)
        .context("manifest generation overflow")?;
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

fn classify_recovery_error(error: &anyhow::Error) -> (RecoveryClass, String) {
    let has = |matches: fn(&(dyn std::error::Error + 'static)) -> bool| error.chain().any(matches);
    let class = if has(|cause| cause.is::<Unsupported>()) {
        RecoveryClass::Unsupported
    } else if has(|cause| cause.is::<NotActiveReader>()) {
        RecoveryClass::Unverifiable
    } else if has(|cause| cause.is::<ForeignRepository>()) {
        RecoveryClass::Discontinuous
    } else if has(|cause| {
        cause.is::<ObjectUnavailable>()
            || cause.is::<MissingStorageHead>()
            || cause
                .downcast_ref::<io::Error>()
                .is_some_and(|source| source.kind() != io::ErrorKind::InvalidData)
    }) {
        RecoveryClass::Unavailable
    } else if error.downcast_ref::<InvalidState>().is_some() {
        RecoveryClass::Invalid
    } else {
        RecoveryClass::Unverifiable
    };
    (class, format!("{error:#}"))
}

/// Marks a failure of authenticated content as proven invalid, unless the
/// content is merely in a format this implementation does not support.
fn proven_invalid(error: anyhow::Error) -> anyhow::Error {
    if error.chain().any(|cause| cause.is::<Unsupported>()) {
        error
    } else {
        error.context(InvalidState)
    }
}

fn validate_pinned_head(chain: &[OpenedState], floor: Option<&ContinuityFloor>) -> Result<()> {
    let current = chain.first().context("manifest chain is empty")?;
    let Some(floor) = floor else {
        return Ok(());
    };
    if floor.repository_root != current.manifest.repository_root {
        bail!("remote repository root changed")
    }
    if current.manifest.policy_generation < floor.policy_generation {
        bail!("remote policy rolled back")
    }
    if current.manifest.generation < floor.generation {
        bail!(
            "remote manifest rolled back from generation {} to {}",
            floor.generation,
            current.manifest.generation
        )
    }
    let pinned = chain
        .iter()
        .find(|entry| entry.manifest.generation == floor.generation)
        .context("remote manifest chain ended before pinned generation")?;
    if pinned.id != floor.head_id {
        bail!("remote manifest history forked from the locally pinned head")
    }
    Ok(())
}

fn record_rejected_head(
    checkout: &Checkout,
    head_id: &str,
    classification: RecoveryClass,
    reason: &str,
) -> Result<()> {
    let path = checkout.directory.join("rejected-heads.json");
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
    write_json(&path, &log)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{
        ForeignRepository, InvalidState, MissingStorageHead, NotActiveReader, ObjectUnavailable,
        RecoveryClass, Unsupported, classify_recovery_error,
    };

    #[test]
    fn recovery_classification_ignores_storage_controlled_message_text() {
        for text in [
            "parse manifest header: unknown field `unsupported`",
            "checkpoint transitions are reserved but not implemented",
            "device is not an active reader of the current generation",
            "key file belongs to a different repository",
            "carrier object 00 is unavailable",
            "encrypted repository has no storage HEAD",
            "recovery manifest byte budget exhausted",
            "authenticated repository state is invalid",
        ] {
            let (class, _) = classify_recovery_error(&anyhow::anyhow!(text.to_owned()));
            assert_eq!(class, RecoveryClass::Unverifiable, "{text}");
        }
    }

    #[test]
    fn recovery_classification_follows_error_types_through_context() {
        let cases: [(anyhow::Error, RecoveryClass); 9] = [
            (
                Unsupported("manifest format 99".to_owned()).into(),
                RecoveryClass::Unsupported,
            ),
            (NotActiveReader.into(), RecoveryClass::Unverifiable),
            (ForeignRepository.into(), RecoveryClass::Discontinuous),
            (
                ObjectUnavailable {
                    storage: "carrier",
                    id: "00".to_owned(),
                    source: None,
                }
                .into(),
                RecoveryClass::Unavailable,
            ),
            (MissingStorageHead.into(), RecoveryClass::Unavailable),
            (
                io::Error::from(io::ErrorKind::InvalidData).into(),
                RecoveryClass::Unverifiable,
            ),
            (InvalidState.into(), RecoveryClass::Invalid),
            (
                anyhow::anyhow!("manifest body digest mismatch").context(InvalidState),
                RecoveryClass::Invalid,
            ),
            (
                anyhow::Error::from(NotActiveReader).context(InvalidState),
                RecoveryClass::Unverifiable,
            ),
        ];
        for (error, expected) in cases {
            let error = error.context("read manifest");
            assert_eq!(classify_recovery_error(&error).0, expected, "{error:#}");
        }
    }
}
