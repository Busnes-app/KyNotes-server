# KyNotes standalone installation

## Before you start

These steps are for a **new, independent installation** from this repository. Use the
README’s upgrade/restore procedure for an existing instance. Keep its volumes, keys,
configuration and Compose overlays; do not replace its environment files with examples.

Use Linux with Docker Engine and Docker Compose 2.24 or newer, Git, and permission to use Docker.
Choose a release/revision and use its matching Compose files and documentation. Image tags
can move: follow the README/Compose attestation and digest-pinning procedure before relying
on a published image. Source builds use the separate build overlay where provided.

Clone this repository, enter its directory, then run the product steps below:

```sh
git clone https://github.com/Busnes-app/KyNotes-server.git
cd KyNotes-server
```

Each service needs its own directory and persistent storage. Several products use host
port 8080 by default; install them on separate hosts or configure distinct host ports and
matching public origins. For remote users, provide a TLS reverse proxy and a hostname you
control. Trust only the proxy’s actual peer address, and forward the original scheme/client
address according to the product’s proxy guide.

## Install the notebook service

A current browser and local administrator/everyday accounts are sufficient; KyIdentity is
optional. Serve remote users over HTTPS.

```sh
[ -e .env ] || (umask 077; touch .env)
chmod 600 .env
```

Compose uses external network `kypost-net` and static IP `10.89.0.7`. Check it with
`docker network inspect kypost-net`. If absent and the subnet is unused, create it:

```sh
docker network create --subnet 10.89.0.0/24 --ip-range 10.89.0.128/25 kypost-net
```

An existing network must include `KYNOTES_IP`; choose an unused address/subnet if needed.
The historical network name does not require KyPost. Set `TRUSTED_PROXY_CIDRS` in `.env`
to your TLS proxy’s exact peer address. The base host bind is `127.0.0.1:5870`.

```sh
docker compose config --quiet
docker compose pull
docker compose up -d
docker compose ps
docker compose exec kynotes-server /kynotes-server healthcheck
```

Open the HTTPS proxy origin and complete first-run setup: create a separate administrator
and everyday account, keep recovery codes, then sign in as the everyday user to create a
notebook, note and attachment. Administrators cannot open users’ notebooks.

For a same-host plaintext trial use the [local development override](docs/DEPLOYMENT.md)
(port 8081). That guide explains the overlay selection; a source build also needs
`docker-compose.build.yml` and must keep it selected on later commands.

The named `kynotes_data` volume holds the database and ciphertext blobs. A sealed backup
capsule **excludes blob content**. Set up `KYNOTES_BLOB_TARGET` and test mirror/fetch as
well as capsule recovery before claiming complete recovery. Read
[deployment](docs/DEPLOYMENT.md), [SSO](docs/SSO.md) and [restore](docs/RESTORE.md).
The deployment guide documents SFTP's RSA-2048 minimum, target-key migration and the
credential/transport risks accepted by an explicitly selected SMB/NTLM mirror.

## Keep it recoverable

Preserve the database **and deployment keys**, not just the image. Configure recovery using
the linked restore runbook, retain an independent copy, and complete a scratch restore with
custodian cards before treating recovery as verified. A synthetic drill uses a throwaway
key and does not prove that the real cards are available or correct.

For upgrades, back up first, read the chosen release’s migration notes, and reuse the same
Compose project, volume mounts and overlay selection for every command. `docker compose
pull` followed by `docker compose up -d` updates a published-image installation; a digest pin
must be deliberately changed after verification. A source install must keep its build
overlay and rebuild. `docker compose down -v` deletes managed volumes: it is not an upgrade.

## What verification means

The startup checks above prove only the checks they perform. Use the README’s development
section and the repository CI workflow for source/build tests; a passing health response or
screenshot is not a substitute. Record the revision, commands, environment and skips when
reporting results. Design plans and dated evidence remain records of their stated scope.
