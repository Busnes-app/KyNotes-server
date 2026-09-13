# Changelog

## Unreleased

- `docker-compose.yml` names the published, attested image and no longer builds. A source install
  keeps building only if `docker-compose.build.yml` is in its `COMPOSE_FILE` chain; installs from
  before this change have no such line and must run the snippet in `docker-compose.build.yml`
  once before their first `up -d` on this revision, then confirm with `docker compose config
  --images` (`kynotes-server:local` is source; the `ghcr.io` name is published).
- KyNotes Server implementation through the current protocol and deployment
  hardening work.
- Local verification image digest: `sha256:57803753d9700377401a857b10f51e78e767e0b4aecfe73ba6fca2b86f2d36e7`.
