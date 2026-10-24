---
title: "Unsealing OpenBao with phone approval"
weight: 90
---

This fork adds an example one-shot worker for an initialized OpenBao node using Shamir 2-of-3 shares. It reuses Revaulter's encrypted CLI/browser protocol. The worker does not introduce another cryptographic service or a new HTTP API.

The fork supports explicitly selected PRF protection or Bitwarden unlock-secret protection; a missing PRF result never changes modes. A successful passkey verification and local unlock can keep the primary key in the current tab's memory for at most two minutes. The server fixes the deadline at verification time; approving requests never extends it. Each request still requires an explicit Approve click.

Each click obtains a separate single-use grant bound to the pending request, owner, credential, session and key epochs. The server checks the live unlock lease again when consuming the grant atomically with confirmation. Expiry, logout, revocation, cancellation or rotation prevents use. Sensitive settings changes clear the request unlock window and still require fresh verification.

Only encrypted key wrappers and public credential metadata are saved in same-origin local storage, so reloads and notification tabs can resume a live login. Restoration checks the current server identity, credential protection and key epoch. Reloading locks local keys; the next approval unlocks the tab again. Signing out removes the saved wrappers. The unlock secret, PRF output, primary key and lease are never persisted. The tab wipes its retained primary-key buffer on expiry, logout, navigation or an approval failure, and checks the deadline again after asynchronous work. The existing rate limits and session lifetime are unchanged. Upgrading to this session-bound lease format invalidates older session cookies once; sign in after the upgrade, then normal reloads resume the login.

These changes have automated dummy-material tests. A physical Android phone, its passkey provider, OpenBao 2.7.1 and the production network still require operator validation before real unseal material is enrolled. No production deployment is implied by this example.

## Trust boundary

```text
CI -- fixed command --> independent trusted worker -- unseal shares --> OpenBao
                                |
                       Revaulter CLI, encrypted envelopes
                                |
                         Revaulter relay/UI
                                |
                         phone browser + passkey
                                |
                      notification only --> HA --> Android
```

CI and HA receive no shares, plaintext bundle or decryption key. The trusted worker receives plaintext only after approval, submits it to its fixed OpenBao endpoint, reports a small status object, then exits. It must be a separate trust domain from dev, CI and HA. Whoever controls that worker can capture approved shares while they are in use. This arrangement does not protect against a compromised worker at approval time.

The Revaulter server and TLS proxy must also serve honest browser code. A malicious JavaScript update can steal secrets during approval. Asset signatures and `revaulter-cli check` are useful checks, but do not make an actively hostile UI server safe. Keep the browser, extensions, passkey provider and release supply chain within the trusted boundary.

Wrapping two of three shares under one account means one person's passkey can release enough material to unseal. It does not preserve two-person custody. Keep the original independently held recovery shares available outside this workflow.

## Prepare the independent worker

Copy `examples/openbao/worker.py` and adapt `examples/openbao/config.example.json` on a Linux worker. It needs Python 3 and the CLI built from this fork. Use a dedicated unprivileged account, an absolute path to the CLI, an operator-owned configuration and a writable private runtime directory for its lock file. CI must not be able to change the configuration, encrypted bundle, executable, trust store or request credential.

The worker accepts only a fixed HTTPS OpenBao origin, verifies its TLS certificate, disables proxy environment use and refuses redirects. Configure `ca_file` for a private CA or omit it to use system trust. Install the Revaulter CA in the CLI's system trust store when needed; do not disable TLS verification.

Use a worker with swap disabled and core dumps disabled, and exclude its process memory from VM snapshots. The worker disables its own core dumps, including in its CLI child. Python strings, browser JavaScript strings and WebCrypto key objects cannot be reliably erased on demand. The implementation overwrites mutable secret buffers, releases references and exits the worker; it does not claim guaranteed physical memory erasure.

Revaulter, its database, TLS, DNS and network access must remain available while OpenBao is sealed. Their bootstrap dependencies cannot require secrets fetched from that same sealed OpenBao. Preserve the Revaulter database, original `secretKey`, credential recovery information and CLI trust store outside that dependency cycle.

## Enroll using dummy material first

1. Choose a stable HTTPS approval origin. Changing the WebAuthn relying-party identity later is not a transparent migration.
2. Explicitly choose PRF protection with a PRF-capable passkey, or Bitwarden protection with an ordinary Bitwarden passkey and the generated unlock secret described below. Use an ordinary browser such as Chrome, rather than assuming an embedded HA WebView supports the same extensions. Verify the exact Android/browser/provider combination. A synced passkey may exist on other devices, and user verification may use the device PIN instead of biometrics.
3. Configure the relay's `openBaoEnrollmentPath` as an absolute path in private persistent storage and `openBaoUrl` as the fixed HTTPS OpenBao origin. The relay writes this directory; the worker mounts it read-only. Both settings must be configured together, and the relay's `baseUrl` must also be HTTPS. Set the worker's `enrollment_file` to that same bundle.
4. Sign in and open **Settings → OpenBao**. Any signed-in, ready account may enroll or replace the shared bundle after fresh passkey verification. The latest successfully saved bundle is used, and unseal approval requests go to the account that saved it. No user ID or request-key copy is required. The account's Request key authentication must be enabled so the worker can send approval requests; if disabled, the page explains this before accepting any shares.
5. Enter two distinct BASE64 unseal shares and choose **Encrypt and enroll**. Start with dummy shares in a disposable test deployment. The page clears its masked inputs, obtains fresh passkey verification and the selected local unlock factor, encrypts the target-bound bundle in the browser, then uploads only the encrypted envelope. Revaulter saves it atomically with the account's request credential and public trust pin, in a mode-0600 file. A failed save preserves the previous complete bundle. Saving enrollment does not unseal OpenBao or verify that the shares belong to it.
6. Raw shares are not written to local storage, session storage, IndexedDB, caches, logs or network requests. Inputs ask password managers not to save them; mutable plaintext and derived-key buffers are cleared on completion, error or departure. Browser code cannot guarantee erasure of immutable strings, prevent a phone clipboard manager from retaining copied text, or control extensions that ignore autofill attributes. Keep clipboard history off and do not save the share fields in a password manager. The existing encrypted login wrappers are separate from the entered shares.
7. Run the dummy integration against disposable endpoints first: `python3 -m unittest discover -s examples/openbao -v`. Only after testing the actual phone's unlock ceremony, cancellation, worker TLS and recovery should the operator enroll real shares. Never put real plaintext on dev, CI or HA, or in Git, shell commands or a CI secret.

The enrollment file is server-managed state, not an Ansible secret-generation output. Back it up together with the Revaulter database and original instance keys, independently of OpenBao. The worker reads one complete file generation, materializes only its request credential and public trust pin in a private temporary directory, and removes those temporary files when the CLI operation ends. The original offline recovery shares remain necessary. If the account's Revaulter request key is rotated, enroll again to refresh the saved request credential.

If this account or passkey was previously used with the unpatched client, assume its PRF wrapping factor may have been disclosed to its server. Do not assume upgrading recovers secrecy for previously wrapped primary keys. Use a new account/root key and re-enroll protected material; assess previously exposed shares separately. There is no automatic migration or fallback to the old unlocked-key behavior.

## Bitwarden setup

Select **Bitwarden passkey and unlock secret** during signup. Save the displayed, locally generated 256-bit unlock secret as the password in the same dedicated Bitwarden login item as this Revaulter passkey. It is not your Bitwarden master password, OpenBao shares or the CI request token. Confirm that you saved it before finishing signup. Revaulter sends neither this secret nor a password verifier to the server; only encrypted key wrappers leave the browser.

Use an item-specific **Regular expression** URI match restricted to the approval HTTPS origin. For the homelab origin, the rule is `^https://revaulter\.hollinger\.asia(?:/.*)?$`. Remove unrelated URI entries from this dedicated item. Bitwarden's default **Base domain** matching covers sibling hosts, and **Host** also matches HTTP. Android URI matching has limitations, so physically verify that autofill is offered at the intended HTTPS origin and not at HTTP, a sibling host or a lookalike before real enrollment. See [Bitwarden URI matching](https://bitwarden.com/help/uri-match-detection/).

For each request, verify the operation and origin before clicking Approve. When the tab is locked, complete the ordinary passkey ceremony and autofill this Revaulter item password. During the remaining two-minute window, later explicit approvals need no additional prompt. Canceling either step leaves the request unapproved. The browser clears the secret input and temporary byte buffers after success, cancellation or error; only the bounded primary-key copy remains after a successful unlock. JavaScript strings cannot be reliably overwritten; this relies on the trusted browser and Bitwarden process, not a guarantee of forensic memory erasure. Only the primary key may remain in this tab’s RAM until the server-bounded unlock deadline; the secret, PRF output and anchor key are released after unlocking.

This mode has a different trust boundary from PRF: possession of the unlock secret and encrypted wrapper is sufficient to recover the primary key offline. The secret is stored and synchronized by Bitwarden; the ordinary WebAuthn passkey authenticates approvals but does not cryptographically supply the wrapping key. Fresh user verification does not guarantee a fresh fingerprint prompt when the provider is already unlocked. Keep Bitwarden's own device and vault protections appropriate to this tradeoff.

Existing PRF credentials keep their original encrypted material. Adding a credential explicitly selects its protection mode. To add Bitwarden to an existing PRF account, generate and save its unlock secret in the dedicated Bitwarden login item before registering the new credential. Verify both credentials can decrypt dummy data under the same anchor fingerprint before removing any credential. Never substitute a fixed PRF value or derive encryption keys from WebAuthn signatures.

The phone unwraps Revaulter's primary key and processes the encrypted request. During an authorized unseal, the trusted worker still briefly receives the plaintext shares in RAM before submitting them to OpenBao. CI, HA and shared dev receive neither the unlock secret nor those shares.

## Invoke from CI without returning material

Allow CI to invoke only a fixed worker command, for example through an SSH key with an operator-configured forced command and forwarding/PTY disabled. The fixed command is `python3 /opt/openbao-worker/worker.py /etc/openbao-worker/worker.json`. Do not give CI shell access to the worker or let it supply a target URL, envelope, executable or CLI flags. That constrained access must be configured and reviewed by the operator; this example does not change SSH or deploy a service.

The worker checks seal state before requesting approval. It validates the exact 2-of-3 target, requests decryption and blocks for up to five minutes. Concurrent invocations receive an already-pending error. On approval it validates the target and both distinct base64 shares before submitting either. It checks again for another operator's unseal and stops once the target is unsealed. It never resets partial progress, changes the seal, or initializes a node.

Success is `{"status":"unsealed"}` or `{"status":"already-unsealed"}`. Failures use a nonzero exit status and a generic error without subprocess output or OpenBao response bodies. CI should continue only after a successful fixed worker command and its own seal-status check. A notification delivery receipt is not approval or unseal success. Do not enable shell tracing, process output recording or debug logging around the worker.

## Use Home Assistant only for notification

Configure Revaulter's generic `plain` webhook to an HA webhook automation. For a private LAN HA endpoint, set `webhookAllowPrivateAddresses: true`. Permit only the required worker/relay-to-HA notification route. The HA automation should ignore the body and send a fixed message with Android `data.clickAction` set to the known HTTPS Revaulter origin.

HA holds no Revaulter request key, unseal shares, password, passkey or approval callback. The notification opens the approval page; it cannot authorize decryption. A compromised HA can delay notifications or suggest a misleading link, so verify the known approval origin before unlocking. Home Assistant setup is described in its [webhook documentation](https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger) and [Companion notification URL documentation](https://companion.home-assistant.io/docs/notifications/notifications-basic/#opening-a-url).

## Recover and validate

Keep another usable passkey and independently stored original shares. Loss of the Revaulter database or original `secretKey` is not repaired by having a passkey alone. Test restoration on an isolated instance without altering production.

Before adoption, unlock the tab and test two consecutive decrypt requests within the two-minute window. Each must require its own explicit Approve click, without another unlock prompt or extension of the deadline. Canceling a request must leave it unapproved. After expiry, logout or reload, verify that approval requires a new passkey ceremony and local unlock; canceling that unlock must not reuse the expired or cleared keys. Also test an expired request, wrong password, unavailable phone, unreachable HA, worker timeout, TLS failure, duplicate shares and an already-unsealed node. Record the exact phone, Android version, browser and provider. Automated software-authenticator tests establish code behavior, not physical biometric verification.
