# Security

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/combinatrix-ai/git-remote-e2ee/security/advisories/new)
rather than opening a public issue.

`git-remote-e2ee` is an early prototype and has not been independently
audited. Its intended guarantees and known limits are listed in the
[README](README.md#security-model) and specified in [docs/design.md](docs/design.md) and
[docs/spec.md](docs/spec.md). Reports are especially welcome about:

- plaintext, refs, paths, or other inner metadata reaching storage;
- accepting tampered, rolled-back, or forked state that a returning clone
  should reject;
- a revoked device obtaining keys for later generations;
- authorization bypass between reader, writer, and administrator roles;
- key material leaking into logs, Git configuration, or the remote.

Limits already documented, such as rollback shown to a fresh clone or metadata
visible to storage, are not vulnerabilities by themselves. Proposals to close
them are still welcome as issues.
