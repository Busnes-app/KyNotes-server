# Purpose

Mirror immutable note-version and attachment ciphertext through the shared offsite module.

# Contracts

- No custom transport or plaintext payload; remote object names are `blobs/<sha256>`.
- Use the immutable shared offsite version in go.mod. SFTP requires RSA-2048 or supported
  Ed25519/ECDSA keys and maintained negotiation; pins never exempt short keys. SMB remains
  explicit legacy interoperability with the risks in docs/DEPLOYMENT.md, refused by config
  under `GODEBUG=fips140=on` (docs/STRONG-CRYPTO.md); no automatic credential, pin,
  destination or replica-history rewrite.
- One destination. Target identity includes account-relative namespace and SFTP pin,
  excludes passwords, and includes the shared endpoint/bucket/prefix identity.
- Acknowledge only successful transfer; verify digest and size on `ErrObjectExists`.
- Sync honors supplied snapshot inventory. Fetch trusts restored blob rows, not replicas.
- Preserve the seekable source passed to Put so S3 can hash/rewind without buffering.
  The shared transports enforce cancellation on upload reads.
- Verify local sources and fetched size/hash. Close every remote reader, abort temporary
  files on failure, and replace corrupt local files only after replacement verifies.
- Report missing objects separately from other failures. Never delete remote history.
- The 16-minute operation budget is bounded and retries skip acknowledgements. Later
  target deletion requires fetch or a future scrub; pending counts are not a scrub.

# Verification

`go test -race ./internal/mirror ./internal/backup ./cmd/kynotes-server` covers retries,
changed target identity, corrupt/interrupted transfers, GC races, a file larger than the
capsule cap, pinned SFTP round trip, and synthetic capsule-plus-blob restoration.
`TestSFTPTransportPolicy` additionally refuses pinned RSA-1024/2047 and SHA-1-only key
exchange before password authentication, keeps failed blobs pending and retains strong
RSA/Ed25519 mirror/fetch controls.
