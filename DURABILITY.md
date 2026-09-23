# Filesystem durability

This describes what a successful filesystem publication promises, what it does
not promise, and how to run the Windows virtual-power-cut harness. The native
Windows and virtual-power-cut results below were verified on 2026-09-23.

## Publication sequence

Client continuity state (`state.json`), filesystem `HEAD`, and immutable
objects use the same flush rules:

1. Create any missing directory that will hold the published name, then flush
   each created directory and the deepest ancestor that already existed.
   A relative path is anchored at the process working directory; `.` and `..`
   are left for the operating system to resolve. Ancestors above the
   preexisting directory are not flushed. If that ancestor cannot be flushed,
   creation fails and the directories this call created are removed when
   possible. A failed create is unacknowledged.
2. Write a temporary file and `File::sync_all` it. Return the error if that
   fails.
3. Publish the name.
   - `state.json` and `HEAD` use `rename` in the destination directory and
     replace an existing file.
   - Immutable objects use `hard_link` from `.staging/<temp>` to
     `objects/<prefix>/<id>`. Those are different directories on the same
     filesystem. An existing path is not replaced. Its bytes are hashed and
     must equal the object id; otherwise the call fails and the file is left
     untouched.
4. Flush the parent directory of the published name. Opening that directory or
   flushing it, if it fails, fails the publication. Success is not returned
   when this step fails.

`FilesystemStorage::initialize` creates `objects`, `manifests`, and `policies`
with the same directory helper, so the storage root (the preexisting ancestor)
is flushed when those directories are new. A later object shard flushes the new
`<prefix>` directory and `objects`, not the storage root again. Client state
creates `.git/git-remote-e2ee/<remote>` the same way and stops at `.git` when
that directory already exists.

The carrier-Git backend does not use this helper. Its compare-and-swap is the
fast-forward push of `refs/heads/git-remote-e2ee`.

`KeyFile::write_new` still creates the final file in place and flushes that
file only. It does not flush the parent directory. That path is outside this
storage fix.

## Unix

The directory flush is `open` plus `sync_all` (`fsync`) on the parent
directory. `fsync` reports an error on failure. It does not prove that a drive
with a volatile write cache stored the sector.

## Windows

`File::open` on a directory followed by `sync_all` is not used. A directory
handle opened with access `0` or `GENERIC_READ` can succeed and then
`FlushFileBuffers` fails with `ERROR_ACCESS_DENIED` (os error 5).

The helper opens the directory with Rust `OpenOptionsExt`:

| Parameter | Value |
| --- | --- |
| `access_mode` | `GENERIC_WRITE` (`0x40000000`) |
| `share_mode` | `7` = `FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE` |
| disposition | `OPEN_EXISTING` (`3`), by not setting create or truncate |
| `custom_flags` | `FILE_FLAG_BACKUP_SEMANTICS` (`0x02000000`) |

`sync_all` is `FlushFileBuffers` on that handle. Open and flush errors both
fail the publication.

A Windows 11 NTFS API probe with a limited user observed `FlushFileBuffers`
returning success on that handle. That probe is not a crash or power-loss
result. Crash evidence is still pending.

`MoveFileExW` / `MOVEFILE_WRITE_THROUGH` is not used. `HEAD` and client state
still use rename. Objects still use a hard link across `.staging` and
`objects/<prefix>/`. `ReplaceFileW` / `REPLACEFILE_WRITE_THROUGH` is not used;
that flag is unsupported.

## What a returned success means

After the function returns `Ok`:

- the temporary file's bytes were flushed before the name was published;
- the new directory entry was published;
- every directory created for that publication was flushed through the
  preexisting ancestor;
- the parent-directory flush of the published name returned success.

After acknowledged success, a later hard power cut must show the new complete
state: client generation 2, `HEAD` successor id, or the successor object.
The baseline immutable object must still contain its original bytes.

Before the function returns, including after the file flush and after the
rename or link but before the directory flush, a hard power cut must show
either the complete baseline or the complete successor. A truncated file, a
JSON fragment, a `HEAD` that is not one of the two fixture ids, or a successor
object with the wrong bytes is a failure. Missing baseline object bytes are a
failure at every stage.

A process killed with `TerminateProcess` or `child.kill` is not a power cut.
The harness below waits so a hypervisor can cut power while the guest is still
inside the selected stage.

## Limits that remain

- Flush success does not prove a disk cache honored the request.
- Directories above the preexisting ancestor are not flushed. `.staging` is
  not a published name; losing it loses only an unfinished write.
- A failed directory create removes the directories that call created when it
  can. If cleanup cannot remove them, a retry sees an existing directory and
  does not flush ancestors. Those leftover entries are unacknowledged. A failed
  publication must be revalidated; it does not prove that an earlier unflushed
  ancestor entry is durable.
- A directory flush that fails after `rename` or `hard_link` returns an error
  and does not roll the name back. The name may already be visible. That error
  is not success.
- Storage can still freeze, delete, or equivocate. Client pins detect rollback
  only for state that was durably recorded.
- The experiment below kills the guest/QEMU process; the underlying host and
  storage remain powered. Physical power loss and other filesystems remain
  unverified.

## Verified Windows results (2026-09-23)

Code revision: `a40a193be85fccc6c837dce03680a87f654dc579`.
Windows 11 on NTFS, in a nested QEMU/KVM VM using a qcow2 disk with
`cache=none` and `no-flush=false`.

- All 63 native Windows tests passed under a limited user token. The one
  ignored test is the externally controlled power-cut harness.
- Host format, all-target tests, and Clippy with warnings denied passed, as
  did Windows-target Clippy and cross-builds. GitHub CI passed.
- Nine virtual power cuts passed, one per cell below. The harness ran as
  SYSTEM through the guest agent, using isolated fixture data and no real
  repository keys.

| Operation | After file flush, before publication | After publication, before directory flush | After persistence returned success |
| --- | --- | --- | --- |
| Client state | Complete old state | Complete old state | Complete new state |
| Filesystem HEAD | Complete old HEAD | Complete old HEAD | Complete new HEAD |
| Immutable object | New object absent | New object absent | Complete new object |

The baseline immutable object retained its exact bytes in all three cases.
The pre-acknowledgement checks permit complete old or new state; every
pre-acknowledgement cut in this run recovered the old state. This demonstrates
that returning from rename/link alone did not establish persistence in these
observations. It is not a controlled comparison against a separate no-flush
implementation.

The guest connected to an external listener before mutation. At the selected
checkpoint the listener immediately issued `docker kill --signal KILL` against
the VM container. Receipt to completion of the kill took 0.421–0.554 seconds.
No graceful shutdown, snapshot, or extra guest disk flush occurred in that
interval. The VM was then started and the fixture read back.

After the third cut Windows entered Automatic Repair; choosing Restart
returned it to normal boot, and the client-state acknowledgement check passed.
The remaining six cases used a clean reboot before setting up each new trial.
Windows recovery policy was not disabled. These are nine finite observations,
not proof of durability across all timing windows, storage devices, or physical
host power failures.

Library-test executable SHA-256:
`7c0da9605391e6ccc26476fe43614313475c61103e2b94bb9b1bad500da5ed09`.

Windows API references: [directory handles](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-handle-to-a-directory),
[FlushFileBuffers access requirements](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

## Power-cut harness

The harness is the ignored library test
`persist::tests::durability_power_cut_harness`. It is compiled only into the
test binary (`cfg(test)`). `git-e2ee` and `git-remote-e2ee` do not contain the
hook, do not read these variables, and do not wait.

`cargo test` skips ignored tests. Do not treat a kill of this process as a
power-loss result.

The fixture must be an empty directory created for this experiment. Do not
point it at a Vault, a real key file, or a personal repository. The Windows
VM directory for the parent runner is `C:\Users\codex\e2ee-durability-test`.

### Environment

| Variable | Values |
| --- | --- |
| `E2EE_DURABILITY_FIXTURE` | Absolute fixture directory |
| `E2EE_DURABILITY_OP` | `client_state`, `head`, or `object` |
| `E2EE_DURABILITY_MODE` | `setup`, `mutate`, or `check` |
| `E2EE_DURABILITY_STAGE` | `after_file_flush`, `after_name_publish`, `after_acknowledge` (mutate and check) |
| `E2EE_DURABILITY_TCP` | Required for `mutate`. `172.18.0.1:18765`. Missing and loopback addresses are rejected. Not used by `setup` or `check`. |

`setup` deletes only that op's subdirectory, writes the baseline, and exits.
`mutate` requires the baseline, connects to `E2EE_DURABILITY_TCP` before the
successor write, performs that write through the real callsite, and waits at
the stage. `check` exits 0 when the on-disk result matches the stage rules
above, and panics otherwise.

Ops are isolated inside the fixture:

- `client_state` → `<fixture>\client\state.json` via `persist_client_state`
- `head` → `<fixture>\head\HEAD` via `FilesystemStorage::compare_and_swap_head`
- `object` → `<fixture>\object-store\objects\<prefix>\<id>` via `put_object_if_absent`

Payloads are fixed ASCII fixtures, not keys:

- client baseline / successor: `e2ee-durability-client-v1` / `v2` (SHA-256 ids, generations 1 and 2)
- head baseline / successor: `e2ee-durability-head-v1` / `v2`
- object bytes: `e2ee-durability-object-v1` / `v2`

### Stages

| Stage | Where the wait happens |
| --- | --- |
| `after_file_flush` | After `sync_all` on the temp file, before rename or hard link |
| `after_name_publish` | After rename or hard link returns, before the directory flush |
| `after_acknowledge` | After the real persistence function has returned `Ok` |

### Checkpoint protocol

The outer listener binds `172.18.0.1:18765` before `mutate` starts. It expects
one ASCII line, at most 512 bytes, ending in a single LF.

`mutate` opens a `TcpStream` to `E2EE_DURABILITY_TCP` before it writes the
successor. There is no guest listener, no accept thread, and no default
loopback address. A missing endpoint or a loopback address fails the test
before that write.

At the selected stage the same socket does `write_all` and `flush` of exactly:

```text
E2EE_DURABILITY_CHECKPOINT op=<op> stage=<stage>
```

with a trailing LF and no further bytes. The process then sleeps. The listener
cuts power after reading that line. Restoring the guest is outside this
repository. The observed results are recorded above.

Stdout may contain `E2EE_DURABILITY_CONNECTED ...` after the TCP connection and
before the successor write. That line is not the checkpoint. The guest opens
the TCP connection itself. A guest agent that only captures stdout after exit
will not see the process while it is waiting.

There is no production environment backdoor. The variables are read only by
this ignored test.

### Windows commands

Build on a machine with Rust and `cargo-zigbuild` (not on the VM):

```text
cargo zigbuild --target x86_64-pc-windows-gnu --tests
cargo zigbuild --release --target x86_64-pc-windows-gnu --bins
```

Copy the library test executable (the one whose `--list` output contains
`persist::tests::durability_power_cut_harness`) to the VM. Release helper
binaries are not the harness. Guest fixture root:
`C:\Users\codex\e2ee-durability-test`.

Run one op and one stage at a time, nine cuts in total (3 ops × 3 stages).
Start the outer listener first. Repeat setup after each cut before the next
mutate. Example for client state, cut before publication:

```powershell
$exe = "C:\Users\codex\e2ee-durability-test\git_remote_e2ee-test.exe"
$env:E2EE_DURABILITY_FIXTURE = "C:\Users\codex\e2ee-durability-test"
$env:E2EE_DURABILITY_OP = "client_state"
$env:E2EE_DURABILITY_MODE = "setup"
$env:E2EE_DURABILITY_STAGE = ""
Remove-Item Env:E2EE_DURABILITY_TCP -ErrorAction SilentlyContinue
& $exe --ignored --exact persist::tests::durability_power_cut_harness --nocapture --test-threads=1

$env:E2EE_DURABILITY_MODE = "mutate"
$env:E2EE_DURABILITY_STAGE = "after_file_flush"
$env:E2EE_DURABILITY_TCP = "172.18.0.1:18765"
& $exe --ignored --exact persist::tests::durability_power_cut_harness --nocapture --test-threads=1
```

After the guest is back:

```powershell
$env:E2EE_DURABILITY_FIXTURE = "C:\Users\codex\e2ee-durability-test"
$env:E2EE_DURABILITY_OP = "client_state"
$env:E2EE_DURABILITY_MODE = "check"
$env:E2EE_DURABILITY_STAGE = "after_file_flush"
Remove-Item Env:E2EE_DURABILITY_TCP -ErrorAction SilentlyContinue
& $exe --ignored --exact persist::tests::durability_power_cut_harness --nocapture --test-threads=1
```

A passing check prints:

```text
E2EE_DURABILITY_CHECK op=client_state stage=after_file_flush result=pass observed=old
```

`observed` is `old` or `new` for the two pre-ack stages, and must be `new`
for `after_acknowledge`. Run the same three modes for `head` and `object`, and
for stages `after_name_publish` and `after_acknowledge`.

`object` checks additionally fail if `e2ee-durability-object-v1` bytes change.

The existing host test `end_to_end::rejects_storage_head_rollback_after_fetch_pins_history`
covers rollback rejection with a key generated in a temporary directory. It is
not a power-cut test and must not be pointed at a real key.
