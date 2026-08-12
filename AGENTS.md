# Repository guidance

- Keep the storage contract backend-neutral. Filesystem behavior must not leak into encrypted repository semantics.
- Do not invent cryptographic primitives. Use established AEAD, signature, hashing, and key-wrapping libraries.
- Treat storage as malicious for confidentiality and integrity, but document availability, rollback, freeze, and equivocation limits precisely.
- Run `cargo fmt --check`, `cargo test --all-targets`, and `cargo clippy --all-targets -- -D warnings` after changes.
- Never commit repository key files or decrypted test data. Test secrets must live only in temporary directories.

