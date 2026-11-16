# Getting started

## Deploy

Follow the deployment guide for persistent storage, HTTPS and proxy trust. The normal Compose service does not publish a host port. The local development overlay publishes loopback 8081 and is not an internet-facing TLS deployment.

## First accounts

The web first-run flow creates separate administrator and everyday accounts. Replace temporary passwords at first sign-in and securely retain the recovery codes shown by account setup. An administrator cannot open ordinary notes using the administrator identity.

## Verify a note

Sign in as the everyday account, create a test note and reopen it. Test an attachment separately. Before depending on recovery, configure both the sealed-capsule destination and the ciphertext-blob mirror; the capsule alone does not contain all attachment data.
