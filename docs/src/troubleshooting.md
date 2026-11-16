# Troubleshooting

- **No browser access after Compose start:** check the expected proxy network/HTTPS route or the deliberate local override.
- **Administrator cannot open notes:** use the separate everyday identity; this separation is intentional.
- **SSO stops working after upgrade:** follow the linked-account migration and re-login/re-pairing steps in the SSO guide.
- **Notes restored but attachments missing:** recover the ciphertext blob mirror as well as the capsule.
- **Health reports 503:** investigate startup readiness and database connectivity; `/livez` alone does not prove readiness.
- **Recovery code used:** securely retain its replacement; codes are single-use.

When reporting a problem, include the product version, platform, failed task and a redacted error. Exclude pairing links, device secrets, recovery codes, custodian shares and private content.
