<p align="center">
  <img src="icon-dark.svg" alt="Revaulter icon" width="60" height="60" />
</p>

# Revaulter: Encrypt, decrypt, and sign with passkeys

This fork adds fresh passkey verification for each approval, keeps PRF results client-only, and includes a [trusted-worker OpenBao example](docs/content/examples/unsealing-openbao-with-phone-approval.md). Changes require operator review and real-device validation before use with live unseal shares.

**[📚 Read the docs](https://revaulter.italypaleale.me)**

Encryption keys and signing keys don't belong in environment variables or on disk. Revaulter keeps them in your passkey: scripts submit a request with the CLI, you approve it in your browser with a passkey, and the browser performs the crypto locally. Everything is End-to-End Encrypted (E2EE) between the CLI and your browser.

**What you can use Revaulter for:**

- [Encrypt/decrypt messages, secrets, keys](https://revaulter.italypaleale.me/examples/encrypt-and-decrypt-short-messages)
- [Unlock encrypted disks at boot](https://revaulter.italypaleale.me/examples/unlocking-luks-encrypted-drives-at-boot)
- [Protect backup repository passwords](https://revaulter.italypaleale.me/examples/backing-up-with-restic)
- [SSH logins with a passkey-backed SSH agent](https://revaulter.italypaleale.me/examples/authenticate-to-ssh-servers)
- [Sign release binaries from CI](https://revaulter.italypaleale.me/examples/signing-a-release-binary-from-github-actions)
- [Issue long-lived JWTs](https://revaulter.italypaleale.me/examples/issuing-a-long-lived-jwt)
- [Encrypt/decrypt very large files with age and Revaulter](https://revaulter.italypaleale.me/examples/encrypting-large-files-with-age-and-revaulter)
- [Use `revaulter-edit` to work with local, encrypted files](https://revaulter.italypaleale.me/cli/revaulter-edit)

![Screenshot of Revaulter, showing 3 requests pending approval: one for encrypting, one for signing, one for decrypting](./screenshot.webp)

## Key features

- **Passkey-derived keys** — encryption keys are derived from WebAuthn passkeys (with PRF) directly in the browser; the server never has access to them
- **End-to-end encryption** — all cryptographic operations happen in the user's browser using WebCrypto, the server stores only opaque, encrypted envelopes
- **Self-hosted** — runs on your infrastructure, you own your data and keys
- **Webhook notifications** — get notified on Discord, Slack, or any webhook endpoint when a request is waiting
- **Lightweight** — single binary, requires only a database (SQLite or PostgreSQL)
- **Strong cryptography** — includes support for hybrid, quantum-resistant asymmetric cryptography

## Quick start

Build this fork first. Published upstream binaries and container images do not include these changes. Use Go 1.27.3+, Node 24 and the pinned pnpm version from `client/web/package.json`:

```sh
(cd client/web && pnpm install --frozen-lockfile && pnpm build)
mkdir -p .bin/linux-amd64
CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -o .bin/linux-amd64/revaulter ./cmd/revaulter
CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -o .bin/linux-amd64/revaulter-cli ./cmd/cli
docker build -t revaulter-phone-approval:local .
```

The example above targets Linux amd64. Run the locally built image with Docker:

```yaml
# docker-compose.yml
services:
  revaulter:
    image: revaulter-phone-approval:local
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/revaulter/config.yaml:ro
      - ./data:/data
    restart: unless-stopped
```

Create a minimal `config.yaml`:

```yaml
webhookUrl: "https://discord.com/api/webhooks/..."
databaseDSN: "/data/revaulter.db"
secretKey: "<generate with: openssl rand -base64 32>"
baseUrl: "https://revaulter.example.com"
```

Then start the server, open the web UI, and create your first account.

## Documentation

The [upstream website](https://revaulter.italypaleale.me) documents the base project. Fork-specific approval and OpenBao instructions live in the [local example](docs/content/examples/unsealing-openbao-with-phone-approval.md).

Quick links:

- [What is Revaulter](https://revaulter.italypaleale.me/docs/what-is-revaulter/) — how it works, security model, webhooks
- [Installing Revaulter](https://revaulter.italypaleale.me/docs/installing-revaulter/) — Docker setup, configuration reference, Docker Compose and Podman examples
- [Using the CLI](https://revaulter.italypaleale.me/docs/revaulter-cli/) — commands, flags, and examples
- [Editing encrypted files](https://revaulter.italypaleale.me/cli/revaulter-edit/) — `revaulter-edit`, for reading and editing local encrypted files
- [Using Revaulter as a Go library](https://revaulter.italypaleale.me/advanced/go-library/) — submit requests from your own applications
- [Cryptography architecture](https://revaulter.italypaleale.me/docs/crypto-architecture/) — key layers, wrapping, derivation, transport encryption

## License

Revaulter is open source software released under a permissive MIT license. See [LICENSE](./LICENSE).
