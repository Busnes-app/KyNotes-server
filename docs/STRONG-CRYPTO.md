# Key strength and the Go TLS profile

[Security policy](../SECURITY.md) · [Deployment](DEPLOYMENT.md) · [SSO](SSO.md) · [Assurance case](ASSURANCE-CASE.md)

This guide covers the keys KyNotes' own code (the server, `kynotes-mcp`, `kynotes-probe` and
the browser client) generates, accepts and verifies, and the optional process setting that
restricts its outbound TLS to strong certificate keys and its blob mirror to SSH or TLS. It is
not a FIPS certification and does not certify a deployment. Stock upstream components beside
KyNotes keep their own policies; see [Out of scope](#out-of-scope).

## Preserve existing data and keys

Keep the database, `secrets/pairing.key`, `secrets/serversalt.key`, `secrets/vapid.key`, the
recovery public-key pin, sealed KyRecovery token, local capsules, the blob store and its
mirror, and custodian cards. Keep the same data volume and the same Compose image/build,
LAN-DNS and local overlays. A refused key is a reason to replace that one credential at its
source, never to regenerate deployment secrets, reset identities, rotate notebook keys or
delete accounts. Nothing in this guide rewrites a stored key.

## Key rules in every mode

| Boundary | Default | Smaller keys |
| --- | --- | --- |
| Notebook content, names, comments, attachments (browser, `kynotes-mcp`) | 32-byte container keys; AES-256-GCM under HKDF-SHA256 subkeys bound to container, object and kind | Refused: `asContentKey` and Go `notecrypto` require 32 bytes, and the browser's only AES import refuses any key that is not 256 bits. |
| Share links | A fresh 32-byte key in the URL fragment, AES-256-GCM | A fragment that decodes to 16 or 24 bytes is refused before WebCrypto sees it (`web/src/crypto.ts`). |
| Identities and team-key envelopes | X25519 identity keys; new envelopes HPKE Auth (X25519, HKDF-SHA256, ChaCha20-Poly1305); stored v2 envelopes open read-only | Fixed suites: keys, version byte and length must agree; no size is selectable. |
| Identity wraps | AES-256-GCM under a 32-byte key derived with PBKDF2-SHA256 (600 000 iterations) from the password or from the 128-bit recovery code | Login iterations below 600 000 are refused, apart from the documented one-time upgrade of a legacy 100 000-iteration account; recovery iterations are a client constant, never read from the server. |
| Device linking | X25519, HKDF-SHA256, ChaCha20-Poly1305, SHA-256 commitments | Fixed suite. |
| Browser vault key | Non-extractable AES-256-GCM generated in the browser | Not imported. |
| Passwords and recovery codes on the server | Argon2id (`ky-primitives/password`) over a 256-bit derived login secret | scrypt verifiers are refused. |
| Deployment secrets (`pairing.key`, `serversalt.key`) | 32 random bytes | A file that does not decode to exactly 32 bytes is a startup error and is never replaced; `KYNOTES_SECRETS_*` values below 32 bytes are refused. |
| Web push (VAPID) | P-256 ES256 key in `secrets/vapid.key` | Fixed curve. Pushes carry no payload, so subscription keys are neither used nor kept. |
| OIDC ID tokens and back-channel logout tokens | RS256 only, verified by `ky-primitives/oidcverify` against the provider's JWKS | Login and logout use the same verifier type: a JWKS RSA key below 2048 bits is never used, so a token it signed is refused. Issuer, authorization, token and JWKS URLs must be HTTPS without credentials; discovery, token and JWKS redirects are refused. |
| Directory webhook (HMAC-SHA256) | 32 random bytes minted by KySignOn | A new secret below 16 bytes is refused by the admin SSO form, KySignOn pairing and `apply-setup`; `syncauth` refuses to verify with one. A short secret stored before this check is kept as is and authenticates nothing until replaced. Pairing requires an HTTPS issuer. |
| KyRecovery capsules | Sealed by `ky-primitives/recoveryclient` to the pinned fixed-suite public key, HTTPS only | No size is selectable. |
| SFTP blob mirror (`ky-primitives/offsite`) | Pinned SHA-256 host key; password or PEM key | Host, client and certificate-authority keys must be RSA-2048+, ECDSA P-256+ or Ed25519, and a matching pin never exempts a short key. RSA client signatures use SHA-2 only; negotiation uses `golang.org/x/crypto/ssh`'s supported set. See [mirror](DEPLOYMENT.md#ciphertext-blob-mirror). |
| S3 blob mirror | HTTPS to AWS, SigV4 (HMAC-SHA256) | A custom `s3_endpoint` may be plain HTTP outside the profile. |
| SMB blob mirror | NTLM (MD4, HMAC-MD5, RC4) | An explicit legacy choice ([SMB](DEPLOYMENT.md#smb-compatibility-choice)); refused under the profile. |
| Generated tokens | Session tokens 256 random bits and device secrets 192, stored as SHA-256 hashes; CSRF tokens HMAC-SHA256 under a key derived from `pairing.key` | Not operator-supplied. |

## Enable the strong profile

Set `GODEBUG=fips140=on` for the server and for every CLI run that contacts a peer, such as
`restore` fetching from the mirror. Use `on`; KyNotes is not tested under the diagnostic
`only` mode. The profile:

- applies Go's FIPS 140-3 TLS policy to every Go TLS client: certificate chains whose every
  certificate, including a root you trust explicitly, uses RSA-2048+, ECDSA P-256/P-384/P-521
  or Ed25519 keys. That covers OIDC discovery, token exchange and JWKS, KySignOn pairing,
  KyRecovery deposits and restore, web push, the S3 mirror, and `kynotes-mcp` and
  `kynotes-probe` connecting to an HTTPS server;
- refuses an `smb://` blob target and a plain-HTTP `s3_endpoint` at startup, with an error
  naming the setting. Move the mirror to pinned SFTP, HTTPS S3 or `file://` first; the existing
  remote history and replica rows are untouched.

Certificate and hostname verification stay on. A private CA does not waive the floor:
replace a weak chain, never disable verification.

For Compose, append `docker-compose.strong-crypto.yml` to the chain you already use (keep the
build, LAN-DNS and local overlays), for example in `.env`:

```sh
COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml:docker-compose.strong-crypto.yml
```

then `docker compose up -d --force-recreate`. The base file lists its environment
explicitly, so `GODEBUG` in `.env` alone does not reach the container; the overlay forwards
only that one variable. If you need other `GODEBUG` entries, put them all in one value with
`fips140=on`. For a native process or systemd unit, add `GODEBUG=fips140=on` to its
environment and restart; a shell export does not reach a running service.

`python3 docs/check-strong-crypto-compose.py` renders five chains (base, each overlay alone,
all overlays) with synthetic inputs, starts nothing, and fails if the overlay changes
anything but that one variable.

To turn the profile off, remove the overlay (or the variable) and recreate the container.

## Configure the independent HTTPS edge

KyNotes serves plain HTTP for its reverse proxy and needs HTTPS in the browser (WebCrypto).
Bind it to the proxy only (Compose binds `127.0.0.1` by default) and set
`TRUSTED_PROXY_CIDRS` to the proxy's own address. Terminate TLS 1.2/1.3 with a verified
RSA-2048+ or P-256+ certificate chain. For Nginx/OpenSSL:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'DEFAULT@SECLEVEL=2';
```

`GODEBUG` does not configure the proxy or browsers. Check the edge before rollout.

## Out of scope

These ship beside KyNotes or are reached by it, but are stock upstream software with their own
key and TLS policy. This guide makes no claim about them:

- **Reverse proxies** in front of KyNotes, and their certificates.
- **Browsers**: TLS to the edge, WebCrypto and the push service a browser chooses.
- **Identity providers** (KySignOn or any OIDC provider): their signing keys beyond the JWKS
  floor above, their TLS servers and their own sessions.
- **Remote SFTP, S3 and SMB servers** and **push services**: their storage, host
  configuration and TLS servers, beyond the key floors KyNotes enforces as their client.
- **KyRecovery** and other suite services: each has its own guide.

## Verification

CI runs the full race suite twice, plainly and with `GODEBUG=fips140=on`, then the Compose
check. The regressions cover:

- `internal/sso/strong_crypto_test.go`: OIDC discovery to a P-256 leaf under an explicitly
  trusted 1024- or 2047-bit RSA root is refused under the profile and accepted otherwise; a
  2048-bit root is accepted in both modes. It logs which mode ran.
- `internal/httpapi/strong_crypto_test.go`: real RS256 ID and logout tokens from 1024- and
  2047-bit JWKS keys refused, 2048 accepted, each through a cold login verifier and a separate
  cold logout verifier.
- `internal/httpapi/sso_test.go` `TestAdminSSOAndPairing`: a 15-byte directory secret from the
  admin form or KySignOn is refused and the stored one kept; pairing never contacts plain HTTP.
- `internal/sso/sso_test.go` `TestShortDirectorySecretIsRefusedNotRewritten`: 15 bytes
  refused, 16 accepted, a pre-existing short secret neither rewritten nor blocking other saves.
- `internal/applysetup/request_test.go`: a short directory secret makes the bundle invalid.
- `internal/config/blob_target_test.go` `TestStrongProfileRefusesNTLMAndPlainS3`: SMB and
  plain-HTTP S3 refused only under the profile; it logs which mode ran.
- `web/src/crypto.test.ts`: share links sealed with AES-128 or AES-192 keys are refused.
- `TestSFTPTransportPolicy` (`internal/mirror`): RSA-1024/2047 SFTP host keys refused.

Local tests use generated keys and local servers; they do not prove a live provider, proxy
or storage server. After rollout check sign-in, logout, a mirror run, a deposit and a restore
drill.

References: [Go FIPS 140-3 mode](https://go.dev/doc/security/fips140),
[NIST SP 800-131A Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf).
