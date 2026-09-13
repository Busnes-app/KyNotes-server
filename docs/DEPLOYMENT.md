# KyNotes Server deployment

Run the container behind an HTTPS reverse proxy on the same Docker network. The
embedded web client is served at `/`; `/api/` is served by the same process.
The compose service does not publish a host port. Set `server.behind_proxy`
and list only the proxy networks in `trusted_proxies`; the proxy must forward
the client address through `X-Forwarded-For`.

For local/LAN access without a reverse proxy, use the development override. Overlays are
selected once through `COMPOSE_FILE` in `.env` (a source build adds `docker-compose.build.yml`;
an explicit `-f` list would drop it):

```bash
# Existing install? Your .env is kept: the copy below never overwrites one, and the build overlay is
# appended to the COMPOSE_FILE chain you already have (a LAN-DNS override survives). A source install must set it before its first `up -d` on this checkout,
# or a bare `up -d` pulls the published image instead of rebuilding.
# Installs from before the published image existed have no COMPOSE_FILE line yet: run this block once,
# then confirm with `docker compose config --images` (must print kynotes-server:local, not the ghcr.io name).
(umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env \
  && cf=$({ grep '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-) && cf=${cf:-docker-compose.yml} \
  && case ":$cf:" in *:docker-compose.build.yml:*) ;; *) cf="$cf:docker-compose.build.yml";; esac && case ":$cf:" in *:docker-compose.local.yml:*) ;; *) cf="$cf:docker-compose.local.yml";; esac \
  && { grep -v -e '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } > "$t" \
  && printf 'COMPOSE_FILE=%s\n' "$cf" >> "$t" && mv "$t" .env)
docker compose up -d
```

It publishes `8081` on the host's loopback address and forwards it to the server's
internal port `8080`. For LAN access set `KYNOTES_LOCAL_BIND=0.0.0.0` in `.env`; the
listener is plaintext HTTP. Do not use this override for an internet-facing deployment.

The default compose file uses the named `kynotes-data` volume for `/data`.
Restart without `--volumes` to preserve notes:

```bash
docker compose down
docker compose up -d
```

Do not run `docker compose down --volumes` unless you intentionally want to
delete the KyNotes database and encrypted blobs. Confirm the mount before a
maintenance restart:

```bash
docker inspect "$(docker compose ps -q kynotes-server)" --format '{{range .Mounts}}{{.Destination}} <- {{.Name}}{{"\n"}}{{end}}'
```

The server applies read-header, read, write, idle, and graceful-shutdown
timeouts from the configuration. Keep the default non-root container,
read-only root filesystem, dropped capabilities, and `/data`/`/tmp` writable
mounts.

## Accounts

`kynotes-server user add --username <name> --password <pass> [--admin]` creates an
account and prints its recovery code once:

```
recovery code: xxxx-xxxx-xxxx
```

Store it offline. It is single-use, it unlocks the account without the password,
and the server keeps only an Argon2id hash of it. `POST /api/v1/auth/recover`
consumes it and returns a fresh one in the response.

Passwords are stored as Argon2id (64 MiB, t=3, p=4). Databases created before this
change hold scrypt verifiers, which are refused; recreate them.

## Backup settings

| Variable | Default | Meaning |
|---|---|---|
| `KYNOTES_BACKUP_DIR` | empty | Directory for sealed `.kycap` copies. The container is read-only, so mount one (`./backups:/backups`) and point this at it. Empty disables local copies. |
| `KYNOTES_BACKUP_KEEP` | `7` | Newest N local copies kept. Must be at least 1. |
| `KYNOTES_BACKUP_DEPOSIT_INTERVAL` | `24h` | Default schedule. `0` disables; the floor is `15m`. The admin UI setting overrides this. |
| `KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY` | `false` | Admit a KyRecovery on a private or carrier-grade NAT address. HTTPS is still required; loopback, link-local and reserved ranges stay refused. |
| `KYNOTES_DNS` | unset | Only with `docker-compose.lan-dns.yml`: the LAN resolver the container uses, for a KyRecovery that resolves only there. Set it in `.env` next to `COMPOSE_FILE` (every later compose command needs it once the overlay is in the chain) and recreate the container. |

The snippet appends `docker-compose.lan-dns.yml` to whatever `COMPOSE_FILE` chain `.env` already
holds (build overlay, local override) and leaves the rest of the chain alone; the resolver
sits next to it: a resolver you already set is kept, `192.168.1.1` is only the default for a first
run. Re-running it is a no-op. One block for every install type:

```bash
(umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env \
  && cf=$({ grep '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-) && cf=${cf:-docker-compose.yml} \
  && dns=$({ grep '^KYNOTES_DNS=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-) && dns=${dns:-192.168.1.1} \
  && case ":$cf:" in *:docker-compose.lan-dns.yml:*) ;; *) cf="$cf:docker-compose.lan-dns.yml";; esac \
  && { grep -v -e '^COMPOSE_FILE=' -e '^KYNOTES_DNS=' .env || [ $? -eq 1 ]; } > "$t" \
  && printf 'COMPOSE_FILE=%s\nKYNOTES_DNS=%s\n' "$cf" "$dns" >> "$t" && mv "$t" .env)
docker compose up -d --force-recreate
docker inspect KyNotes-Server --format '{{.HostConfig.Dns}}'   # must print the resolver in .env, e.g. [192.168.1.1]
```

The admin Backups section supports pin-by-hand, pairing, local sealed copies,
manual backup, export, drill, unpair and a persisted schedule (off or 15 minutes–366 days).
The loop polls every minute and counts from the last attempt, including failures.
A key without a destination is a precondition failure. A remote failure reports any
local copy that did succeed; a local failure does not cancel the deposit.

Use [RESTORE.md](RESTORE.md) for sealed recovery and the blob-coverage limitations.
CLI `deposit`, `export-capsule --out FILE` and `backup-drill` take the data-directory
lock and require a stopped server; the admin UI operates through the live handle.
`copy-data-dir --out DIR` and `restore-data-dir --in DIR` are local plaintext copies.

Every destructive backup action, including capsule export, uses POST and requires admin step-up plus CSRF;
confirm the account password in the backup screen. HTTP mutations also require CSRF.
Unpair removes URL/token rows only; the KyRecovery admin separately revokes the token.
The suite key, receipts and local copies remain. Pinning a different key is refused.

TLS protects the incoming key, token and receipt. Pin the suite key manually or compare
fingerprints out of band. Preserve existing deployment secrets and token sealer labels.
Shutdown waits for a bounded 16-minute backup operation; Compose allows 17 minutes
before forcibly terminating the process.

## Plaintext copy

Back up with the server stopped: stop the container, copy `/data` as one unit,
then start it. Restore only while stopped, run `integrity-check` and
`consistency-check`, and start the server after both checks pass.

Migrations run at startup. Make a backup before upgrades. To roll back, stop
the server, restore the backup directory, run both integrity checks, and start
again. The server holds a data-directory lock while running, so backup and
restore commands must be run against a stopped service.

## Ciphertext blob mirror

Capsules exclude both note-version and attachment ciphertext files. Configure one
separate destination under `backup.blob_target` in YAML (see `kynotes.example.yaml`):

| YAML field | Environment override | Meaning |
|---|---|---|
| `url` | `KYNOTES_BLOB_TARGET` | `file:///mnt/backup/kynotes`, `s3://bucket/prefix`, `sftp://user@host:22/dir`, or `smb://host/share/dir` |
| `access_key` | `KYNOTES_BLOB_TARGET_ACCESS_KEY` | S3 access ID, SFTP username, or SMB `DOMAIN\user` |
| `secret` | `KYNOTES_BLOB_TARGET_SECRET` | S3 secret, SFTP password/PEM private key, or SMB password |
| `host_key` | `KYNOTES_BLOB_TARGET_HOST_KEY` | Verified SFTP SHA256 host fingerprint |
| `s3_endpoint` | `KYNOTES_BLOB_TARGET_S3_ENDPOINT` | Optional HTTPS R2/MinIO endpoint |
| `s3_region` | `KYNOTES_BLOB_TARGET_S3_REGION` | Optional region |

Keep credentials in protected deployment configuration, never URL passwords. Compose
passes these variables through; empty overrides preserve YAML values. Effective mirror
credentials are included only inside the encrypted capsule configuration. Admin status
omits credentials and usernames. Mount a `file://` destination into the container and
make it writable by its user; a directory on the same disk is not off-box protection.

With the server stopped, run `kynotes-server test-blob-target --config PATH`. For SFTP,
an absent pin causes the probe to print the presented fingerprint and fail before
authentication. Compare it with the host's key through a trusted independent channel,
then configure it and repeat. Server startup and uploads require a pin. SFTP paths are
relative to the account root. The probe writes a small object; S3 retains/overwrites
that probe, while the other transports remove it.

SMB supports versions 2/3 and requests signing, but the shared library can accept an
unsigned guest session granted by the server. An impersonating server could observe
the NTLMv2 exchange and discard uploads. Restrict SMB to a trusted network and verify
replicas independently; a host-mounted share accessed with `file://` avoids that client
limitation. An existing SMB object is accepted only after its size and digest verify.

Admin **Mirror now** works independently of capsule pairing. **Back up now** and scheduled
runs mirror the exact collected capsule inventory after attempting the capsule destinations.
Capsule and mirror results remain separate: a deposit receipt does not prove blob coverage.
CLI `mirror-blobs --config PATH` and `fetch-blobs --config PATH` require a stopped server
and take the same directory lock. All transfers stream; the capsule member size cap does
not limit blob transfers. Product upload limits stay unchanged.

The single-target replica table records successful transfers only. Endpoint, bucket,
prefix, SFTP host key and account-relative namespace changes cause uploads again;
password rotations alone do not. Acknowledgements avoid rereading remote objects on
every run, so later remote deletion is detected during fetch, not by the pending count.
Remote objects are never garbage-collected by KyNotes. Preserve them for every retained
capsule; removing live local objects does not establish that old capsules no longer need them.

There is no atomic transaction spanning SQLite, local GC and remote storage. A blob that
vanishes after snapshot collection is reported as a failure against that retained inventory.
Investigate missing content before relying on the capsule. Operations share a 16-minute
budget; very large backlogs may need repeated **Mirror now** runs before a backup. Successful
acknowledgements survive retries. A future resumable worker/remote scrub is the upgrade path
for workloads exceeding that budget or requiring continuous remote verification.

OIDC login aliases use the configured login rate per client IP. The bounded pending
login store evicts its oldest entry when full; an evicted login must start again.
Removed `backup` commands fail with migration guidance rather than starting the server.
Use `copy-data-dir` for the old local copy, `restore-data-dir` for its restore, and
`restore --in CAPSULE --to EMPTY_DIR` for sealed recovery. Server mode accepts flags only.

With `server.behind_proxy: true`, IP-keyed rate limits use X-Forwarded-For only when
its immediate socket peer is in `server.trusted_proxies`. The right-most untrusted
address identifies the client; untrusted peers and malformed suffixes fall back to the
socket address. Trusted proxies must append the observed peer address or replace the
header with the observed client, never blindly pass client-supplied headers. Configure
only actual proxy networks, not all Internet addresses. IPv6 identities retain /64 grouping.
