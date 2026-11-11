use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

use anyhow::{Context, Result, bail};

use crate::catfile::{BatchHeader, CatFile, GitObjectType};
use crate::gitcmd::GitRepository;
use crate::{refname, trace};

pub fn has_complete_object_graph(repo: &GitRepository) -> bool {
    let shallow = match repo
        .git()
        .args(["rev-parse", "--is-shallow-repository"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };
    if String::from_utf8_lossy(&shallow.stdout).trim() != "false" {
        return false;
    }

    let partial = match repo
        .git()
        .args([
            "config",
            "--local",
            "--name-only",
            "--get-regexp",
            r"^(extensions\.partialclone|remote\..*\.promisor)$",
        ])
        .output()
    {
        Ok(output) => output,
        Err(_) => return false,
    };
    partial.status.code() == Some(1) && partial.stdout.is_empty()
}

pub fn resolve_ref(repo: &GitRepository, reference: &str) -> Result<String> {
    git_text(repo, &["rev-parse", "--verify", reference])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerRefKind {
    Branch,
    Tag,
}

impl InnerRefKind {
    /// The namespace of a ref whose name was already validated.
    pub fn of(reference: &str) -> Result<Self> {
        if reference.starts_with("refs/heads/") {
            Ok(Self::Branch)
        } else if reference.starts_with("refs/tags/") {
            Ok(Self::Tag)
        } else {
            bail!(
                "unsupported ref namespace for {reference}; only refs/heads/* and refs/tags/* are supported"
            )
        }
    }
}

pub fn validate_inner_ref(reference: &str) -> Result<InnerRefKind> {
    let kind = InnerRefKind::of(reference)?;
    if !refname::is_valid(reference) {
        bail!("invalid Git ref name {reference}")
    }
    Ok(kind)
}

/// Checks every ref of a manifest once, when an operation accepts it. A
/// target must be a full object ID: Git would resolve any other text as a
/// revision expression against the local repository.
pub fn validate_inner_refs(refs: &BTreeMap<String, String>) -> Result<()> {
    for (reference, object) in refs {
        validate_inner_ref(reference)?;
        if !is_object_id(object) {
            bail!("ref {reference} points at {object:?}, which is not a Git object ID")
        }
    }
    Ok(())
}

fn is_object_id(object: &str) -> bool {
    matches!(object.len(), 40 | 64)
        && object
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn ensure_branch_target(
    objects: &mut Objects<'_>,
    reference: &str,
    object: &str,
) -> Result<()> {
    let target = resolve_tag_chain(objects, reference, object, "pushed")?;
    if target.kind != GitObjectType::Commit {
        bail!("branch ref {reference} must resolve to a commit")
    }
    Ok(())
}

pub fn is_ancestor(repo: &GitRepository, ancestor: &str, descendant: &str) -> Result<bool> {
    let status = repo
        .git()
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("git merge-base failed"),
    }
}

/// Object queries for one operation, answered by at most one
/// `git cat-file --batch-check` and one `git cat-file --batch` process,
/// each started on first use.
pub struct Objects<'a> {
    repo: &'a GitRepository,
    check: Option<CatFile>,
    contents: Option<CatFile>,
}

/// Annotated tag headers larger than this are rejected; the message after
/// them is skipped unread.
const MAX_TAG_HEADER_BYTES: u64 = 64 * 1024;

impl<'a> Objects<'a> {
    pub fn new(repo: &'a GitRepository) -> Self {
        Self {
            repo,
            check: None,
            contents: None,
        }
    }

    /// The object's type, or `None` when it is absent. A failure of git is
    /// an error, never absence.
    fn kind(&mut self, object: &str) -> Result<Option<GitObjectType>> {
        let check = match &mut self.check {
            Some(check) => check,
            None => self.check.insert(CatFile::batch_check(self.repo)?),
        };
        match check
            .request(object)
            .context("git cat-file --batch-check failed")?
        {
            BatchHeader::Missing => Ok(None),
            BatchHeader::Object { kind, .. } => Ok(Some(kind)),
        }
    }

    pub fn exists(&mut self, object: &str) -> Result<bool> {
        Ok(self.kind(object)?.is_some())
    }

    /// The `object` and `type` headers of an annotated tag. Only the header
    /// block is read into memory; the message is discarded undecoded.
    fn tag_target(&mut self, reference: &str, tag: &str) -> Result<(String, GitObjectType)> {
        let header = self.tag_header(reference, tag)?;
        let mut target = None;
        let mut target_kind = None;
        for line in header.split(|byte| *byte == b'\n') {
            if let Some(value) = line.strip_prefix(b"object ") {
                if target.replace(value).is_some() {
                    bail!("annotated tag {reference} has duplicate target objects")
                }
            } else if let Some(value) = line.strip_prefix(b"type ")
                && target_kind.replace(value).is_some()
            {
                bail!("annotated tag {reference} has duplicate target types")
            }
        }
        let target = target.context("annotated tag is missing its target object")?;
        if !matches!(target.len(), 40 | 64) || !target.iter().all(u8::is_ascii_hexdigit) {
            bail!("annotated tag {reference} has a malformed target object")
        }
        let target_kind = target_kind.context("annotated tag is missing its target type")?;
        let target_kind = GitObjectType::parse(target_kind)
            .with_context(|| format!("annotated tag {reference} has an unknown target type"))?;
        Ok((
            String::from_utf8(target.to_vec()).expect("hex is ASCII"),
            target_kind,
        ))
    }

    fn tag_header(&mut self, reference: &str, tag: &str) -> Result<Vec<u8>> {
        let contents = match &mut self.contents {
            Some(contents) => contents,
            None => self.contents.insert(CatFile::batch(self.repo)?),
        };
        let size = match contents
            .request(tag)
            .context("git cat-file --batch failed")?
        {
            BatchHeader::Object {
                kind: GitObjectType::Tag,
                size,
                ..
            } => size,
            BatchHeader::Missing => bail!("annotated tag of {reference} disappeared while reading"),
            BatchHeader::Object { .. } => {
                // Its body is pending; this process cannot answer further.
                self.contents = None;
                bail!("annotated tag of {reference} changed type while reading")
            }
        };
        let mut prefix = Vec::new();
        let body = contents.body();
        body.take(size.min(MAX_TAG_HEADER_BYTES))
            .read_to_end(&mut prefix)?;
        let rest = size - prefix.len() as u64;
        if std::io::copy(&mut body.take(rest), &mut std::io::sink())? != rest {
            bail!("git cat-file truncated annotated tag of {reference}")
        }
        contents.end_body()?;
        match prefix.windows(2).position(|pair| pair == b"\n\n") {
            Some(end) => {
                prefix.truncate(end);
                Ok(prefix)
            }
            None if rest == 0 => Ok(prefix),
            None => bail!(
                "annotated tag of {reference} has a header larger than {MAX_TAG_HEADER_BYTES} bytes"
            ),
        }
    }
}

pub struct PackSource {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr: File,
    finished: bool,
    _timer: trace::Span,
}

impl Read for PackSource {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stdout
            .as_mut()
            .expect("pack source stdout is available")
            .read(buffer)
    }
}

impl PackSource {
    pub fn finish(mut self) -> Result<()> {
        self.stdout.take();
        let status = self.child.wait()?;
        self.finished = true;
        if !status.success() {
            bail!(
                "git pack-objects failed: {}",
                read_process_error(&mut self.stderr)
            )
        }
        Ok(())
    }
}

impl Drop for PackSource {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn start_incremental_pack(
    repo: &GitRepository,
    new_refs: &BTreeMap<String, String>,
    old_refs: &BTreeMap<String, String>,
) -> Result<PackSource> {
    let shallow = repo
        .git()
        .args(["rev-parse", "--is-shallow-repository"])
        .output()?;
    if !shallow.status.success() {
        bail!("could not determine whether the source repository is shallow")
    }
    if String::from_utf8(shallow.stdout)?.trim() == "true" {
        bail!("cannot publish from a shallow repository; fetch --unshallow first")
    }
    let timer = trace::Span::new("git_pack_objects_stream_lifetime");
    let stderr = tempfile::tempfile().context("create pack-objects stderr file")?;
    let mut child = repo
        .git()
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
    {
        let input = child
            .stdin
            .as_mut()
            .context("open git pack-objects stdin")?;
        for object in new_refs.values() {
            writeln!(input, "{object}")?;
        }
        for object in old_refs.values() {
            writeln!(input, "^{object}")?;
        }
    }
    child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .context("open git pack-objects stdout")?;
    Ok(PackSource {
        child,
        stdout: Some(stdout),
        stderr,
        finished: false,
        _timer: timer,
    })
}

pub struct PackImporter {
    child: Child,
    stdin: Option<ChildStdin>,
    stderr: File,
    finished: bool,
    _timer: trace::Span,
}

impl Write for PackImporter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stdin
            .as_mut()
            .expect("pack importer stdin is available")
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdin
            .as_mut()
            .expect("pack importer stdin is available")
            .flush()
    }
}

impl PackImporter {
    pub fn finish(mut self) -> Result<()> {
        self.stdin.take();
        let status = self.child.wait()?;
        self.finished = true;
        if !status.success() {
            bail!(
                "git index-pack failed: {}",
                read_process_error(&mut self.stderr)
            )
        }
        Ok(())
    }
}

impl Drop for PackImporter {
    fn drop(&mut self) {
        if !self.finished {
            self.stdin.take();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn start_pack_import(repo: &GitRepository) -> Result<PackImporter> {
    let timer = trace::Span::new("git_index_pack");
    let stderr = tempfile::tempfile().context("create index-pack stderr file")?;
    let mut child = repo
        .git()
        .args(["index-pack", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
    let stdin = child.stdin.take().context("open git index-pack stdin")?;
    Ok(PackImporter {
        child,
        stdin: Some(stdin),
        stderr,
        finished: false,
        _timer: timer,
    })
}

fn read_process_error(file: &mut File) -> String {
    use std::io::Seek;

    let _ = file.rewind();
    let mut message = Vec::new();
    let _ = file.take(16 * 1024).read_to_end(&mut message);
    String::from_utf8_lossy(&message).trim().to_owned()
}

pub fn ensure_refs_connected_since(
    repo: &GitRepository,
    refs: &BTreeMap<String, String>,
    verified_refs: &BTreeMap<String, String>,
) -> Result<()> {
    ensure_refs_connected_with_budget(repo, refs, verified_refs, TreeListingBudget::standard())
}

fn ensure_refs_connected_with_budget(
    repo: &GitRepository,
    refs: &BTreeMap<String, String>,
    verified_refs: &BTreeMap<String, String>,
    mut tree_budget: TreeListingBudget,
) -> Result<()> {
    let _timer = trace::Span::new("git_ref_connectivity_walk");
    if refs.is_empty() {
        return Ok(());
    }
    let mut objects = Objects::new(repo);
    let mut commit_roots = Vec::new();
    let mut verified_commit_roots = Vec::new();
    let mut checked_trees = HashSet::new();
    for (reference, object) in refs {
        let ref_kind = InnerRefKind::of(reference)?;
        let target = resolve_tag_chain(&mut objects, reference, object, "fetched")?;
        match target.kind {
            GitObjectType::Commit => commit_roots.push(target.oid),
            GitObjectType::Tree if ref_kind == InnerRefKind::Tag => {
                if checked_trees.insert(target.oid.clone()) {
                    ensure_tree_connected(
                        repo,
                        &mut objects,
                        reference,
                        &target.oid,
                        &mut tree_budget,
                    )?;
                }
            }
            GitObjectType::Blob if ref_kind == InnerRefKind::Tag => {}
            _ => bail!("fetched ref {reference} does not resolve to a supported Git object"),
        }
    }

    // A successful prior connectivity check makes every object reachable from
    // these tips a trusted frontier. Git objects are immutable and
    // content-addressed, so a later fetch only needs to walk objects newly
    // reachable beyond that frontier. Still require the frontier tips to be
    // present locally so corruption or an unexpected local prune fails closed.
    for (reference, object) in verified_refs {
        let ref_kind = InnerRefKind::of(reference)?;
        let target = resolve_tag_chain(&mut objects, reference, object, "verified")?;
        match target.kind {
            GitObjectType::Commit => verified_commit_roots.push(target.oid),
            GitObjectType::Tree if ref_kind == InnerRefKind::Tag => {
                if checked_trees.insert(target.oid.clone()) {
                    ensure_tree_connected(
                        repo,
                        &mut objects,
                        reference,
                        &target.oid,
                        &mut tree_budget,
                    )?;
                }
            }
            GitObjectType::Blob if ref_kind == InnerRefKind::Tag => {}
            _ => bail!("verified ref {reference} does not resolve to a supported Git object"),
        }
    }

    if commit_roots.is_empty() {
        return Ok(());
    }
    let mut command = repo.git();
    command.args([
        "rev-list",
        "--objects",
        "--no-object-names",
        "--missing=print",
    ]);
    for object in &commit_roots {
        command.arg(object);
    }
    if !verified_commit_roots.is_empty() {
        command.arg("--not");
        for object in &verified_commit_roots {
            command.arg(object);
        }
    }
    let mut output = StreamedGitOutput::spawn(command)?;
    let mut checked_objects = 0;
    let mut line = Vec::new();
    while read_delimited(&mut output.stdout, b'\n', 80, &mut line)? {
        checked_objects += 1;
        if line.first() == Some(&b'?') {
            bail!("fetched refs contain missing Git objects")
        }
    }
    if let Some(reason) = output.finish()? {
        bail!("git connectivity check failed: {reason}")
    }
    trace::count("git_ref_connectivity_walk_objects", checked_objects);
    Ok(())
}

struct StreamedGitOutput {
    child: Child,
    stdout: BufReader<ChildStdout>,
    stderr: File,
    finished: bool,
}

impl StreamedGitOutput {
    fn spawn(mut command: std::process::Command) -> Result<Self> {
        let stderr = tempfile::tempfile().context("create Git command stderr file")?;
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr.try_clone()?))
            .spawn()?;
        let stdout = child.stdout.take().context("open Git command stdout")?;
        Ok(Self {
            child,
            stdout: BufReader::new(stdout),
            stderr,
            finished: false,
        })
    }

    fn finish(&mut self) -> Result<Option<String>> {
        let status = self.child.wait()?;
        self.finished = true;
        Ok((!status.success()).then(|| read_process_error(&mut self.stderr)))
    }
}

impl Drop for StreamedGitOutput {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Git listings can be unexpectedly large or malformed, so read only one
/// bounded record at a time. An unfinished record is not a clean end of output.
fn read_delimited(
    reader: &mut impl BufRead,
    delimiter: u8,
    max_bytes: usize,
    record: &mut Vec<u8>,
) -> Result<bool> {
    record.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if record.is_empty() {
                return Ok(false);
            }
            bail!("Git listing ended inside a record")
        }
        let length = available
            .iter()
            .position(|byte| *byte == delimiter)
            .map_or(available.len(), |position| position + 1);
        if record.len().saturating_add(length) > max_bytes {
            bail!("Git listing record exceeds {max_bytes} bytes")
        }
        record.extend_from_slice(&available[..length]);
        reader.consume(length);
        if record.last() == Some(&delimiter) {
            return Ok(true);
        }
    }
}

struct RefTarget {
    oid: String,
    kind: GitObjectType,
}

fn resolve_tag_chain(
    objects: &mut Objects<'_>,
    reference: &str,
    object: &str,
    label: &str,
) -> Result<RefTarget> {
    let missing = || -> anyhow::Error {
        if label == "verified" {
            anyhow::anyhow!("verified ref {reference} is missing locally")
        } else {
            anyhow::anyhow!(
                "fetched ref {reference} does not resolve to a complete Git object graph"
            )
        }
    };
    let mut current = object.to_owned();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current.clone()) {
            bail!("{label} ref {reference} contains a cyclic tag chain")
        }
        let kind = objects.kind(&current)?.ok_or_else(missing)?;
        if kind != GitObjectType::Tag {
            return Ok(RefTarget { oid: current, kind });
        }
        let (target, expected_kind) = objects.tag_target(reference, &current)?;
        if objects.kind(&target)?.ok_or_else(missing)? != expected_kind {
            bail!("annotated tag {reference} has a mismatched target type")
        }
        current = target;
    }
}

struct TreeListingBudget {
    entries: usize,
    roots: usize,
    max_entries: usize,
    max_roots: usize,
}

impl TreeListingBudget {
    fn standard() -> Self {
        Self {
            entries: 0,
            roots: 0,
            max_entries: 4_000_000,
            max_roots: 256,
        }
    }

    fn begin_root(&mut self, reference: &str) -> Result<()> {
        self.roots = self.roots.saturating_add(1);
        if self.roots > self.max_roots {
            bail!("fetched tag {reference} exceeds the tree-root limit")
        }
        Ok(())
    }

    fn charge(&mut self, reference: &str) -> Result<()> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.max_entries {
            bail!("fetched tag {reference} expands to too many tree entries")
        }
        Ok(())
    }
}

fn ensure_tree_connected(
    repo: &GitRepository,
    objects: &mut Objects<'_>,
    reference: &str,
    tree: &str,
    budget: &mut TreeListingBudget,
) -> Result<()> {
    budget.begin_root(reference)?;
    let mut output = StreamedGitOutput::spawn({
        let mut command = repo.git();
        command.args([
            "ls-tree",
            "-r",
            "-t",
            "--full-tree",
            "--format=%(objectmode) %(objectname)",
            tree,
        ]);
        command
    })?;
    let mut line = Vec::new();
    while read_delimited(&mut output.stdout, b'\n', 80, &mut line)? {
        budget.charge(reference)?;
        let header = std::str::from_utf8(&line[..line.len() - 1])?;
        let mut fields = header.split_ascii_whitespace();
        let mode = fields
            .next()
            .context("Git ls-tree returned an entry without a mode")?;
        let object = fields
            .next()
            .context("Git ls-tree returned an entry without an object ID")?;
        if mode == "160000" {
            // A gitlink names a submodule commit that belongs to another
            // object database and is not part of this tree's connectivity.
            continue;
        }
        if !objects.exists(object)? {
            bail!("fetched tag {reference} contains missing Git object {object}")
        }
    }
    if let Some(reason) = output.finish()? {
        bail!("fetched tag {reference} contains an incomplete tree: {reason}")
    }
    Ok(())
}

pub fn update_ref(repo: &GitRepository, reference: &str, object: &str) -> Result<()> {
    let output = repo
        .git()
        .args(["update-ref", reference, object])
        .output()?;
    if !output.status.success() {
        bail!(
            "git update-ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

pub fn create_tag_if_absent_or_matching(
    repo: &GitRepository,
    reference: &str,
    object: &str,
) -> Result<()> {
    let existing = repo
        .git()
        .args([
            "for-each-ref",
            "--count=1",
            "--format=%(refname) %(objectname) %(symref)",
            reference,
        ])
        .output()?;
    if !existing.status.success() {
        bail!(
            "could not inspect local tag {reference}: {}",
            String::from_utf8_lossy(&existing.stderr).trim()
        )
    }
    for line in String::from_utf8(existing.stdout)?.lines() {
        if let Some(value) = line
            .strip_prefix(reference)
            .and_then(|rest| rest.strip_prefix(' '))
        {
            let (current, symbolic_target) = value
                .split_once(' ')
                .context("Git returned a malformed local tag")?;
            if !symbolic_target.is_empty() {
                bail!("local tag {reference} is symbolic")
            }
            if current == object {
                return Ok(());
            }
            bail!("local tag {reference} already points at a different object")
        }
    }

    // The empty expected old ID makes creation atomic. --no-deref prevents a
    // symbolic tag from forwarding this write to another local reference.
    let created = repo
        .git()
        .args(["update-ref", "--no-deref", reference, object, ""])
        .output()?;
    if !created.status.success() {
        bail!(
            "could not create local tag {reference}: {}",
            String::from_utf8_lossy(&created.stderr).trim()
        )
    }
    Ok(())
}

fn git_text(repo: &GitRepository, args: &[&str]) -> Result<String> {
    let output = repo.git().args(args).output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        TreeListingBudget, ensure_refs_connected_since, ensure_refs_connected_with_budget,
        has_complete_object_graph,
    };
    use crate::gitcmd::GitRepository;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    fn git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn complete_object_graph_rejects_shallow_and_promisor_repositories() {
        let temporary = tempfile::tempdir().unwrap();
        let full = temporary.path().join("full");
        fs::create_dir_all(&full).unwrap();
        let init = Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .arg(&full)
            .output()
            .unwrap();
        assert!(init.status.success());
        git(&full, &["config", "user.name", "Test"]);
        git(&full, &["config", "user.email", "test@example.invalid"]);
        for contents in ["first", "second"] {
            fs::write(full.join("file"), contents).unwrap();
            git(&full, &["add", "file"]);
            git(&full, &["commit", "--quiet", "-m", contents]);
        }
        assert!(has_complete_object_graph(
            &GitRepository::open(&full).unwrap()
        ));

        let shallow = temporary.path().join("shallow");
        let source_url = format!("file://{}", full.display());
        let clone = Command::new("git")
            .args(["clone", "--quiet", "--depth=1", "--no-tags"])
            .arg(source_url)
            .arg(&shallow)
            .output()
            .unwrap();
        assert!(
            clone.status.success(),
            "git clone: {}",
            String::from_utf8_lossy(&clone.stderr)
        );
        assert!(!has_complete_object_graph(
            &GitRepository::open(&shallow).unwrap()
        ));

        git(&full, &["config", "remote.origin.promisor", "true"]);
        assert!(!has_complete_object_graph(
            &GitRepository::open(&full).unwrap()
        ));
        git(&full, &["config", "--unset", "remote.origin.promisor"]);
        git(&full, &["config", "extensions.partialClone", "origin"]);
        assert!(!has_complete_object_graph(
            &GitRepository::open(&full).unwrap()
        ));
    }

    fn repository_with_commit(path: &Path) -> String {
        git(path, &["init", "--quiet", "--initial-branch=main"]);
        git(path, &["config", "user.name", "Test"]);
        git(path, &["config", "user.email", "test@example.invalid"]);
        git(path, &["commit", "--quiet", "--allow-empty", "-m", "first"]);
        let output = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write_tag(
        repo: &Path,
        target: &str,
        target_kind: &str,
        extra_header: &[u8],
        message: &[u8],
    ) -> String {
        let mut bytes = format!(
            "object {target}\ntype {target_kind}\ntag t\ntagger Test <test@example.invalid> 0 +0000\n"
        )
        .into_bytes();
        bytes.extend_from_slice(extra_header);
        bytes.push(b'\n');
        bytes.extend_from_slice(message);
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["hash-object", "-t", "tag", "-w", "--literally", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn make_tree(repo: &Path, entries: &str) -> String {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("mktree")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(entries.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn compact_repeated_tree_tag_is_checked_without_unbounded_expansion() {
        let temporary = tempfile::tempdir().unwrap();
        repository_with_commit(temporary.path());
        let mut tree = make_tree(temporary.path(), "");
        for _ in 0..8 {
            tree = make_tree(
                temporary.path(),
                &format!("040000 tree {tree}\ta\n040000 tree {tree}\tb\n"),
            );
        }
        let first_tag = write_tag(temporary.path(), &tree, "tree", b"", b"first tag\n");
        let duplicate_tag = write_tag(temporary.path(), &tree, "tree", b"", b"second tag\n");
        let refs = BTreeMap::from([
            ("refs/tags/first".to_owned(), first_tag.clone()),
            ("refs/tags/duplicate".to_owned(), duplicate_tag),
        ]);
        let repo = GitRepository::open(temporary.path()).unwrap();
        ensure_refs_connected_since(&repo, &refs, &BTreeMap::new()).unwrap();
        let budget = TreeListingBudget {
            max_entries: 600,
            ..TreeListingBudget::standard()
        };
        ensure_refs_connected_with_budget(&repo, &refs, &refs, budget).unwrap();

        let other_tree = make_tree(temporary.path(), &format!("040000 tree {tree}\tc\n"));
        let other_tag = write_tag(temporary.path(), &other_tree, "tree", b"", b"other tag\n");
        let distinct_refs = BTreeMap::from([
            ("refs/tags/first".to_owned(), first_tag),
            ("refs/tags/other".to_owned(), other_tag),
        ]);
        let budget = TreeListingBudget {
            max_entries: 600,
            ..TreeListingBudget::standard()
        };
        let error =
            ensure_refs_connected_with_budget(&repo, &distinct_refs, &BTreeMap::new(), budget)
                .unwrap_err();
        assert!(
            error.to_string().contains("too many tree entries"),
            "{error:#}"
        );

        let budget = TreeListingBudget {
            max_entries: 600,
            max_roots: 1,
            ..TreeListingBudget::standard()
        };
        let error =
            ensure_refs_connected_with_budget(&repo, &distinct_refs, &BTreeMap::new(), budget)
                .unwrap_err();
        assert!(error.to_string().contains("tree-root limit"), "{error:#}");
    }

    #[test]
    fn tags_with_non_utf8_or_large_messages_are_inspectable() {
        let temporary = tempfile::tempdir().unwrap();
        let commit = repository_with_commit(temporary.path());
        let binary = write_tag(
            temporary.path(),
            &commit,
            "commit",
            b"",
            b"\xff\xfe\x00 not UTF-8\n",
        );
        let large_message = vec![b'x'; 16 * 1024 * 1024];
        let large = write_tag(temporary.path(), &commit, "commit", b"", &large_message);
        let nested = write_tag(temporary.path(), &binary, "tag", b"", b"\xc3\x28\n");
        let refs = BTreeMap::from([
            ("refs/tags/binary".to_owned(), binary),
            ("refs/tags/large".to_owned(), large),
            ("refs/tags/nested".to_owned(), nested),
        ]);
        let repo = GitRepository::open(temporary.path()).unwrap();
        ensure_refs_connected_since(&repo, &refs, &BTreeMap::new()).unwrap();
        ensure_refs_connected_since(&repo, &refs, &refs).unwrap();
    }

    #[test]
    fn tag_headers_beyond_the_bound_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let commit = repository_with_commit(temporary.path());
        let mut header = b"x-padding ".to_vec();
        header.extend(vec![b'a'; 128 * 1024]);
        header.push(b'\n');
        let tag = write_tag(temporary.path(), &commit, "commit", &header, b"message\n");
        let refs = BTreeMap::from([("refs/tags/padded".to_owned(), tag)]);
        let repo = GitRepository::open(temporary.path()).unwrap();
        let error = ensure_refs_connected_since(&repo, &refs, &BTreeMap::new()).unwrap_err();
        assert!(
            format!("{error:#}").contains("header larger than"),
            "{error:#}"
        );
    }

    #[test]
    fn a_failing_git_is_an_error_and_not_a_missing_object() {
        let temporary = tempfile::tempdir().unwrap();
        let commit = repository_with_commit(temporary.path());
        let absent = "0".repeat(commit.len());
        let repo = GitRepository::open(temporary.path()).unwrap();
        let error = ensure_refs_connected_since(
            &repo,
            &BTreeMap::from([("refs/heads/main".to_owned(), commit.clone())]),
            &BTreeMap::from([("refs/heads/gone".to_owned(), absent)]),
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "verified ref refs/heads/gone is missing locally"
        );

        let broken = GitRepository::owned_git_dir(&temporary.path().join("not-a-repository"));
        let error = ensure_refs_connected_since(
            &broken,
            &BTreeMap::from([("refs/heads/main".to_owned(), commit)]),
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(
            error.chain().any(|cause| cause.is::<std::io::Error>()),
            "{error:#}"
        );
        assert!(
            !format!("{error:#}").contains("does not resolve"),
            "{error:#}"
        );
    }
}
