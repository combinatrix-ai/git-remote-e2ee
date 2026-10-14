# Security model

The storage provider is treated as malicious. `git-remote-e2ee` aims to
guarantee:

- confidentiality of inner contents and Git metadata: files, paths, refs,
  object IDs, authors, and messages;
- authenticity and integrity of every fetched state: only devices with write
  authority under the authenticated policy history can author a state that
  conforming clients accept;
- continuity for a clone that has synced before: it rejects any state older
  than, or diverging from, its continuity floor, the newest state it accepted
  after a complete connectivity check or its own successful push;
- that a revoked device gets no keys for generations that conforming writers
  build on top of its revocation.

Write authority is about what clients accept, not about who can put bytes on
the storage. Anyone who can write to the storage, including a read-only member
or someone with only push access to the carrier repository, can still replay
old valid states, hide updates, or corrupt `HEAD`. Clients reject what they
cannot verify, so this can deny service but cannot make unauthorized history
accepted. Restrict storage write access as a separate layer, for example with
read-only repository permissions and branch protection on GitHub.

It does **not** prevent:

- the host or anyone with storage write access deleting data, corrupting
  `HEAD`, or refusing service;
- a brand-new clone, or a clone that has not synced since, being shown an old
  or forked history, or different clients being shown different histories
  (that needs an external anchor, which is on the roadmap);
- a revoked writer or administrator creating a valid-looking fork from before
  its revocation, which clients that never saw the revocation cannot tell apart;
- an authorized writer making destructive changes;
- a revoked device reading what it could read before revocation;
- traffic analysis: update times, object sizes, total growth, and the padded
  reader count are visible;
- future quantum attacks: key exchange uses X25519.

Concurrent pushes cannot silently overwrite each other as long as the storage
honors compare-and-swap, as a Git host's fast-forward check or the directory
backend's lock does.

Keys work as a backward chain. The current key can decrypt all earlier
history, which lets a new device read the whole repository, but an old key
cannot decrypt anything newer. This is key regression, not forward secrecy for
history already published. See [design.md](design.md) and [spec.md](spec.md)
for the full threat model, and [SECURITY.md](../SECURITY.md) to report an issue.

