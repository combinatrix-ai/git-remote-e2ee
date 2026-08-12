use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::crypto::{KeyFile, object_id};
use crate::git;
use crate::manifest::{Manifest, PackDescriptor, open_manifest, seal_manifest};
use crate::storage::{ObjectKind, Storage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
struct ClientState {
    #[serde(default)]
    packs: Vec<String>,
    head_id: Option<String>,
    generation: Option<u64>,
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
        self.commit_manifest(None, Manifest::genesis(self.key.repository_id.clone()))
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
        let (head_id, current, next_object, non_fast_forward) =
            self.preflight_push(repo, remote_name, source_ref, destination_ref, force)?;
        if current.refs.get(destination_ref) == Some(&next_object) {
            return Ok(head_id);
        }

        let mut next_refs = current.refs.clone();
        next_refs.insert(destination_ref.to_owned(), next_object.clone());
        // A forced rewrite may point behind or away from every old ref. Do not
        // exclude the old reachable set in that case: it can contain the new
        // tip itself, producing an empty or incomplete pack.
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
        let encrypted_pack = self.key.seal(&pack, b"git-remote-e2ee pack v1")?;
        let pack_id = object_id(&encrypted_pack);
        self.storage
            .put_object_if_absent(ObjectKind::Pack, &pack_id, &encrypted_pack)?;

        let mut packs = current.packs.clone();
        packs.push(PackDescriptor {
            id: pack_id,
            plaintext_size: pack.len() as u64,
        });
        let next = Manifest {
            format_version: current.format_version,
            repository_id: current.repository_id.clone(),
            generation: current.generation + 1,
            previous: Some(head_id.clone()),
            refs: next_refs,
            packs,
        };
        let next_id = self.commit_manifest(Some(&head_id), next.clone())?;
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
    ) -> Result<(String, Manifest, String, bool)> {
        if !destination_ref.starts_with("refs/heads/") {
            bail!("only refs/heads/* destinations are supported")
        }
        git::ensure_repository(repo)?;
        let (head_id, current) = self.current_manifest()?;
        if let Some(remote_name) = remote_name {
            self.validate_and_pin_manifest(repo, remote_name, &head_id, &current)?;
        }
        let next_object = git::resolve_ref(repo, source_ref)?;
        if current.refs.get(destination_ref) == Some(&next_object) {
            return Ok((head_id, current, next_object, false));
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
        Ok((head_id, current, next_object, non_fast_forward))
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
        let (head_id, manifest) = self.current_manifest()?;
        self.validate_and_pin_manifest(repo, remote_name, &head_id, &manifest)?;
        Ok(manifest)
    }

    pub fn import_packs(&self, repo: &Path, remote_name: &str) -> Result<Manifest> {
        git::ensure_repository(repo)?;
        validate_remote_name(remote_name)?;
        let (head_id, manifest) = self.current_manifest()?;
        let state_path = client_state_path(repo, remote_name)?;
        let state = read_client_state(&state_path)?;
        self.validate_pinned_head(&head_id, &manifest, &state)?;
        let imported: HashSet<String> = state.packs.into_iter().collect();
        let mut all_imported = imported;

        for descriptor in &manifest.packs {
            if all_imported.contains(&descriptor.id) {
                continue;
            }
            let encrypted = self.storage.get_object(ObjectKind::Pack, &descriptor.id)?;
            if object_id(&encrypted) != descriptor.id {
                bail!("pack ciphertext hash mismatch for {}", descriptor.id)
            }
            let pack = self.key.open(&encrypted, b"git-remote-e2ee pack v1")?;
            if pack.len() as u64 != descriptor.plaintext_size {
                bail!("pack plaintext size mismatch for {}", descriptor.id)
            }
            git::import_pack(repo, &pack)?;
            all_imported.insert(descriptor.id.clone());
        }
        write_client_state(&state_path, &all_imported, &head_id, manifest.generation)?;
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
        let imported = state.packs.into_iter().collect();
        write_client_state(&state_path, &imported, head_id, manifest.generation)
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
        let imported = state.packs.into_iter().collect();
        write_client_state(&state_path, &imported, head_id, manifest.generation)
    }

    fn validate_pinned_head(
        &self,
        current_id: &str,
        current: &Manifest,
        state: &ClientState,
    ) -> Result<()> {
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
        let (mut id, mut manifest) = self.current_manifest()?;
        let newest = manifest.clone();
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(id.clone()) {
                bail!("manifest chain contains a cycle")
            }
            for pack in &manifest.packs {
                let encrypted = self.storage.get_object(ObjectKind::Pack, &pack.id)?;
                if object_id(&encrypted) != pack.id {
                    bail!("pack ciphertext hash mismatch for {}", pack.id)
                }
                self.key.open(&encrypted, b"git-remote-e2ee pack v1")?;
            }
            let Some(previous_id) = manifest.previous.clone() else {
                if manifest.generation != 0 {
                    bail!("manifest chain terminated above generation zero")
                }
                break;
            };
            let previous = self.read_manifest(&previous_id)?;
            manifest.validate_successor(&previous_id, &previous)?;
            id = previous_id;
            manifest = previous;
        }
        Ok(newest)
    }

    pub fn current_manifest(&self) -> Result<(String, Manifest)> {
        let head = self
            .storage
            .read_head()?
            .context("encrypted repository is not initialized")?;
        let manifest = self.read_manifest(&head)?;
        Ok((head, manifest))
    }

    fn read_manifest(&self, id: &str) -> Result<Manifest> {
        let encrypted = self.storage.get_object(ObjectKind::Manifest, id)?;
        if object_id(&encrypted) != id {
            bail!("manifest ciphertext hash mismatch")
        }
        open_manifest(&self.key, &encrypted)
    }

    fn commit_manifest(&self, expected: Option<&str>, manifest: Manifest) -> Result<String> {
        let encrypted = seal_manifest(&self.key, manifest)?;
        let id = object_id(&encrypted);
        self.storage
            .put_object_if_absent(ObjectKind::Manifest, &id, &encrypted)?;
        self.storage.compare_and_swap_head(expected, &id)?;
        Ok(id)
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
    generation: u64,
) -> Result<()> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort();
    let state = ClientState {
        packs: values.into_iter().cloned().collect(),
        head_id: Some(head_id.to_owned()),
        generation: Some(generation),
    };
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = path.with_extension(format!("json.{}.tmp", hex::encode(random)));
    let contents = serde_json::to_vec_pretty(&state)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&contents)?;
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
