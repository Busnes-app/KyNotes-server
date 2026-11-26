# Everyday tasks

## Notes and attachments

Use the everyday account to create and edit content in the web app. Verify saved changes by reopening the note. The browser owns content decryption; service administration and possession of database ciphertext do not by themselves grant note access.

## Identity changes

Configure SSO using the supported registration and session-aware logout guide. Upgrades involving linked-account migration can require users to sign in and pair again. Preserve the existing account's recovery access before changing identity settings.

## Backup administration

Administrators can pin the suite public key, pair KyRecovery, schedule backups, keep local sealed copies and run synthetic drills. Configure `KYNOTES_BLOB_TARGET` for the separate ciphertext mirror. A successful synthetic drill does not prove that every real user's keys or every blob can be recovered.

## Restore

Follow the ordered runbook: recover the capsule and deployment secrets, then fetch/verify the missing ciphertext blobs. Local plaintext maintenance commands require the service to be stopped.

For native PostgreSQL recovery rehearsals, the [restore runbook](https://github.com/Busnes-app/KyNotes-server/blob/master/docs/RESTORE.md#prepare-a-native-postgresql-restored-target-tenancy-preparation)
explains the offline restored-target safety command. Hosted startup and backup transport
remain unavailable; preparing a target is not permission to serve it.

## Staff organization metadata (tenancy preparation)

Hosted startup remains unavailable in this release. The prepared staff console lists
organization status and storage-pool metadata. Select an organization under Users to inspect
its accounts and charged bytes, or select Platform/an organization under Audit log. Refresh
re-reads metadata. Customer accounts are managed in KyIdentity; staff metadata access never
opens notes, and there are no customer account, team or sign-in configuration write controls.
Standalone administrators keep the existing console and local account workflows.
