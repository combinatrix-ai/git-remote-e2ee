# Contributing

Issues and pull requests are welcome. For security problems, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Ground rules

- Keep the storage contract backend-neutral. Filesystem behavior must not leak
  into encrypted repository semantics.
- Do not invent cryptographic primitives. Use established AEAD, signature,
  hashing, and key-wrapping libraries.
- Treat storage as malicious for confidentiality and integrity, and document
  availability, rollback, freeze, and equivocation limits precisely.
- Never commit key files or decrypted test data. Test secrets must live only in
  temporary directories.
- Protocol changes must update [SPEC.md](SPEC.md) and, where relevant,
  [DESIGN.md](DESIGN.md) in the same change.

## Build and test

```console
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI runs the same three commands.

The test suite covers:

- incremental push and reconstruction into a fresh repository;
- native clone, fetch, pull, push, dry-run, refspec, and force-push behavior;
- rollback, same-generation fork, and ciphertext-tampering rejection;
- streaming-AEAD chunk boundaries, wrong keys or AAD, reordering, duplication,
  truncation, trailing bytes, forged sizes, and legacy-format rejection;
- independent device add, read, and write, non-admin rejection,
  genesis-substitution rejection, administrative rollback pinning, device
  revocation without pack rewrites, and multi-generation offline catch-up;
- malformed predecessor-link, generation-key commitment, recipient-set, and
  signed-but-incomplete Git object-graph rejection;
- two independent carrier writers racing real `git push` processes, with
  exactly one winner;
- plaintext-absence checks across carrier history;
- applicable black-box scenarios independently reimplemented from Git
  upstream's
  [`t/t5801-remote-helpers.sh`](https://github.com/git/git/blob/master/t/t5801-remote-helpers.sh).

A local bare Git repository is enough for deterministic carrier concurrency
tests: local-path pushes still run Git's real `receive-pack`, ref locking, and
fast-forward checks. Hosted smoke tests remain useful for authentication,
request limits, and provider-specific policy.

## Benchmarks

The opt-in harness in `scripts/` measures encryption, reconstruction,
verification, and incremental updates. See [BENCHMARKS.md](BENCHMARKS.md).
Benchmark outputs, repository keys, and reconstructed data must not be
committed.
