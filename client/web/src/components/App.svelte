<script lang="ts">
import { onMount } from 'svelte'

import AuthAccessView from '$components/AuthAccessView.svelte'
import AuthSetupView from '$components/AuthSetupView.svelte'
import FreshPasswordPrompt from '$components/FreshPasswordPrompt.svelte'
import ReadyView from '$components/ReadyView.svelte'
import UpdateAvailable from '$components/UpdateAvailable.svelte'
import { appVersion, getServerVersion, reloadWithLatestClient, versionsMatch } from '$lib/app-version'
import { argon2idCost } from '$lib/argon2id-cost'
import {
    computeSigningKeyThumbprint,
    deriveRequestEncKeyPair,
    deriveRequestEncMlkemKeyPair,
    deriveSigningKeyPair,
    deriveWrappingKey,
    generatePrimaryKey,
    generateUnlockSecret,
    parseWrappedPrimaryKeyEnvelope,
    signingJwkToPem,
    signingJwkToSshPublicKey,
    unwrapPrimaryKey,
    wrapPrimaryKey,
} from '$lib/crypto'
import {
    type AnchorKeyPair,
    anchorEs384JwkToString,
    anchorMldsa87PubToString,
    generateAnchorKeyPair,
    PUBKEY_BUNDLE_VERSION,
    SIGNING_KEY_PUBLICATION_VERSION,
    serializeAnchorSecret,
    signCredentialAttestationHybrid,
    signPubkeyBundleHybrid,
    signSigningKeyPublicationHybrid,
    unwrapAnchorKey,
    wrapAnchorKey,
} from '$lib/crypto-anchor'
import { type WrappedKeyCache, withFreshKeys } from '$lib/fresh-unlock'
import { ResponseNotOkError } from '$lib/request'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import {
    v2AddCredentialBegin,
    v2AddCredentialFinish,
    v2AddRequestOIDCIssuer,
    v2CreateSigningKey,
    v2DeleteCredential,
    v2DeleteRequestOIDCIssuer,
    v2DeleteSigningKey,
    v2FinalizeSignup,
    v2ListCredentials,
    v2ListSigningKeys,
    v2ListStream,
    v2LoginBegin,
    v2LoginFinish,
    v2Logout,
    v2RegenerateRequestKey,
    v2RegisterBegin,
    v2RegisterFinish,
    v2RenameCredential,
    v2Session,
    v2SetAllowedIPs,
    v2SetRequestAuthMethods,
    v2SetSigningKeyPublished,
    v2UpdateDisplayName,
    v2UpdateWrappedKey,
} from '$lib/v2-api'
import type {
    Argon2idCost,
    DerivedSigningKey,
    V2AuthSessionInfo,
    V2CredentialItem,
    V2PendingRequestItem,
    V2PublishedSigningKey,
    V2RequestAuthMethods,
    V2SessionResponse,
} from '$lib/v2-types'
import { PrfUnavailableError, webauthnLoginWithPrf, webauthnRegister } from '$lib/webauthn'
import { loadWrappedKey, saveWrappedKey } from '$lib/wrapped-key-storage'

type UIState = 'boot' | 'signin' | 'signup' | 'password-login' | 'password-setup' | 'ready'

const missingPrfError = 'Authenticator did not return PRF output'
const signupMissingPrfError =
    'This passkey does not support the PRF extension Revaulter needs to protect your local keys. Sign up with a PRF-capable passkey or use a browser and authenticator that support WebAuthn PRF.'
const addPasskeyMissingPrfError =
    'This passkey does not support the PRF extension Revaulter needs to protect your local keys. Add a PRF-capable passkey or use a browser and authenticator that support WebAuthn PRF.'
const prfHelpHref = 'https://revaulter.italypaleale.me/docs/what-is-revaulter/#supported-passkeys'

let uiState = $state<UIState>('boot')
let serverVersion = $state<string | null>(null)
let authBusy = $state(false)
let authError = $state<string | null>(null)
let pageError = $state<string | null>(null)
let signupDisabled = $state(false)

let displayName = $state('')
let passwordInput = $state('')
let keyProtection = $state<'prf' | 'bitwarden'>('prf')
let loginWrappedPrimaryKey = $state<string | null>(null)
// The credential ID (base64url) of the currently signed-in passkey
let sessionCredentialId = $state<string | null>(null)
let sessionCredentialWrappedKeyEpoch = $state<number>(1)
let loginWrappedKeyStale = $state(false)
// The password exists only while a single key operation is running
let sessionPassword = $state<string | null>(null)
let allowedIpsText = $state('')
let settingsBusy = $state(false)
let settingsError = $state<string | null>(null)
let settingsSuccess = $state<string | null>(null)
const authErrorHelpHref = $derived(authError === signupMissingPrfError ? prfHelpHref : null)
const settingsErrorHelpHref = $derived(settingsError === addPasskeyMissingPrfError ? prfHelpHref : null)
let credentials = $state<V2CredentialItem[]>([])
let signingKeys = $state<V2PublishedSigningKey[]>([])
let hasPassword = $state(false)

let session = $state<V2SessionResponse | null>(null)
let wrappedKeyCache = $state<WrappedKeyCache | null>(null)
let prfSecret = $state<Uint8Array | null>(null)
let primaryKey = $state<Uint8Array | null>(null)
// Unwrapped hybrid anchor keypair for the current action
// Used to sign attestations when adding new credentials
let sessionAnchor = $state<AnchorKeyPair | null>(null)
// Wrapped anchor blob returned by the login finish response, unwrapped once we have the wrapping key
let loginWrappedAnchorKey = $state<string | null>(null)
// Public key (SPKI, base64url) of a freshly-registered credential
// Held briefly until the matching finalize step consumes it
let pendingCredentialPublicKeyHash = $state<string | null>(null)

let items = $state<Record<string, V2PendingRequestItem>>({})
let listConnected = $state(false)
let stopStream: (() => Promise<void>) | null = null
let awaitingReadySessionRefresh = $state(false)

onMount(() => {
    void initialize()
    return () => {
        teardownListStream()
    }
})

async function initialize() {
    authError = null
    pageError = null

    try {
        const currentServerVersion = await getServerVersion()
        if (!versionsMatch(appVersion, currentServerVersion)) {
            serverVersion = currentServerVersion
            return
        }

        const active = await v2Session()
        const cache = loadWrappedKey()
        if (active.authenticated && cache?.userId === active.userId) {
            const credentials = await v2ListCredentials()
            const credential = credentials.find((item) => item.credentialId === cache.credentialId)
            if (
                credential &&
                credential.keyProtection === cache.keyProtection &&
                credential.wrappedKeyEpoch === cache.wrappedKeyEpoch &&
                !credential.wrappedKeyStale
            ) {
                let envelope: ReturnType<typeof parseWrappedPrimaryKeyEnvelope>
                try {
                    envelope = parseWrappedPrimaryKeyEnvelope(cache.wrappedPrimaryKey!)
                } catch (err) {
                    clearLocalAuthState()
                    throw err
                }
                session = active
                wrappedKeyCache = cache
                keyProtection = cache.keyProtection
                sessionCredentialId = cache.credentialId
                sessionCredentialWrappedKeyEpoch = cache.wrappedKeyEpoch
                hasPassword = envelope.passwordRequired
                enterReadyView()
                return
            }
        }
        clearLocalAuthState()
        authError = 'Sign in to refresh the encrypted keys saved in this browser.'
        uiState = 'signin'
    } catch (err) {
        if (err instanceof ResponseNotOkError) {
            if (err.statusCode === 401) {
                clearLocalAuthState()
                uiState = 'signin'
                return
            }
        }

        pageError = err instanceof Error ? err.message : String(err)
        uiState = 'signin'
    }
}

async function reloadForUpdate(): Promise<void> {
    if (!serverVersion) {
        return
    }

    await reloadWithLatestClient()
}

function toSessionResponse(authSession: V2AuthSessionInfo): V2SessionResponse {
    return {
        authenticated: true,
        userId: authSession.userId,
        displayName: authSession.displayName,
        requestKey: authSession.requestKey,
        requestKeyEnabled: authSession.requestKeyEnabled,
        requestOidcEnabled: authSession.requestOidcEnabled,
        requestOidcIssuers: authSession.requestOidcIssuers ?? [],
        anchorFingerprint: authSession.anchorFingerprint,
        wrappedKeyEpoch: authSession.wrappedKeyEpoch,
        allowedIps: authSession.allowedIps,
        ttl: authSession.ttl,
    }
}

let keyOperationBusy = false
let keyOperationEpoch = 0
let passwordPrompt = $state<((value: string | null) => void) | null>(null)

function clearUnlockedKeys() {
    primaryKey?.fill(0)
    prfSecret?.fill(0)
    sessionAnchor?.mldsa87.seed.fill(0)
    primaryKey = null
    prfSecret = null
    sessionAnchor = null
    sessionPassword = null
}

async function withFreshLocalKeys<T>(
    use: (grant: string) => Promise<T>,
    requestState?: string,
    requestAction?: 'add-credential' | 'update-wrapped-key'
): Promise<T> {
    if (keyOperationBusy || !session || !sessionCredentialId || !wrappedKeyCache) {
        throw new Error('Finish the current verification before starting another action')
    }
    keyOperationBusy = true
    const operationEpoch = keyOperationEpoch
    const expectedUserId = session.userId
    try {
        return await withFreshKeys({
            cache: wrappedKeyCache,
            requestState,
            requestAction,
            authorize: async () => {
                const active = await v2Session()
                const activeCredentials = await v2ListCredentials()
                const credential = activeCredentials.find((item) => item.credentialId === sessionCredentialId)
                if (
                    operationEpoch !== keyOperationEpoch ||
                    active.userId !== expectedUserId ||
                    !credential ||
                    credential.wrappedKeyEpoch !== wrappedKeyCache?.wrappedKeyEpoch
                ) {
                    throw new Error('The session or passkey changed; sign in again before approving')
                }
                session = active
            },
            getPassword: () =>
                new Promise((resolve) => {
                    passwordPrompt = resolve
                }),
            use: async (keys) => {
                if (operationEpoch !== keyOperationEpoch || session?.userId !== expectedUserId || uiState !== 'ready') {
                    throw new Error('The approval session ended; sign in and try again')
                }
                primaryKey = keys.primaryKey
                prfSecret = keys.prfSecret ?? null
                sessionAnchor = keys.anchor
                sessionPassword = keys.password ?? null
                return await use(keys.approvalGrant)
            },
        })
    } finally {
        passwordPrompt = null
        clearUnlockedKeys()
        keyOperationBusy = false
    }
}

async function withApprovalKey<T>(state: string, use: (key: Uint8Array, grant: string) => Promise<T>): Promise<T> {
    return await withFreshLocalKeys(async (grant) => {
        if (!primaryKey) {
            throw new Error('Fresh passkey verification did not unlock a key')
        }
        return await use(primaryKey, grant)
    }, state)
}

function answerPasswordPrompt(value: string | null) {
    const resolve = passwordPrompt
    passwordPrompt = null
    resolve?.(value)
}

function setPrfSecret(v: Uint8Array) {
    prfSecret = v
}

async function teardownListStream() {
    const stop = stopStream
    if (stop) {
        await stop()
    }
    stopStream = null
    listConnected = false
}

function clearLocalAuthState() {
    passwordInput = ''
    keyOperationEpoch += 1
    answerPasswordPrompt(null)
    clearUnlockedKeys()
    void teardownListStream()
    session = null
    wrappedKeyCache = null
    saveWrappedKey(null)
    prfSecret = null
    primaryKey = null
    sessionAnchor = null
    loginWrappedAnchorKey = null
    pendingCredentialPublicKeyHash = null
    loginWrappedPrimaryKey = null
    sessionCredentialId = null
    sessionCredentialWrappedKeyEpoch = 1
    loginWrappedKeyStale = false
    sessionPassword = null
    allowedIpsText = ''
    settingsError = null
    settingsSuccess = null
    signingKeys = []
}

function enterReadyView() {
    clearUnlockedKeys()
    saveWrappedKey(wrappedKeyCache)
    uiState = 'ready'
    passwordInput = ''
    authError = null
    settingsError = null
    settingsSuccess = null
    allowedIpsText = session?.allowedIps.join('\n') ?? ''
    startListStream()
    void doLoadCredentials()
    void doLoadSigningKeys()
}

function openSignIn() {
    authError = null
    passwordInput = ''
    loginWrappedPrimaryKey = null
    uiState = 'signin'
}

function openSignup() {
    authError = null
    passwordInput = ''
    loginWrappedPrimaryKey = null
    uiState = 'signup'
}

async function returnToSignIn() {
    if (session) {
        await doLogout()
        return
    }
    openSignIn()
}

function sessionLabel() {
    if (!session) {
        return ''
    }
    return session.displayName.trim() || session.userId
}

async function beginPasskeyLoginStep(): Promise<'authenticated' | 'password-required'> {
    const sensitiveBuffers: Uint8Array[] = []
    let unownedPrf: Uint8Array | undefined
    try {
        primaryKey = null
        sessionAnchor = null
        sessionPassword = null
        loginWrappedPrimaryKey = null
        loginWrappedAnchorKey = null
        loginWrappedKeyStale = false

        const begin = await v2LoginBegin()
        const assertion = await webauthnLoginWithPrf({
            challenge: begin.challenge,
            prfSalt: base64UrlToBytes(begin.basePrfSalt),
            options: begin.options,
            requirePrf: false,
        })
        unownedPrf = assertion.prfSecret
        const finish = await v2LoginFinish({
            challengeId: begin.challengeId,
            credential: (assertion.raw as { credential?: unknown })?.credential ?? {
                id: assertion.id,
                signCount: assertion.signCount,
            },
        })

        if (!finish.authenticated || !finish.session) {
            throw new Error('Login did not complete')
        }
        keyProtection = finish.keyProtection
        if (keyProtection !== 'prf' && keyProtection !== 'bitwarden') {
            throw new Error('Unsupported key protection')
        }
        if (keyProtection === 'prf' && (!assertion.prfSecret || assertion.prfSecret.length === 0)) {
            throw new Error(missingPrfError)
        }

        session = toSessionResponse(finish.session)
        if (assertion.prfSecret) {
            setPrfSecret(assertion.prfSecret)
            unownedPrf = undefined
        }
        sessionCredentialId = assertion.id
        const publicKey = (begin.options as { publicKey?: { rpId?: string } })?.publicKey
        wrappedKeyCache = {
            keyProtection,
            userId: finish.session.userId,
            credentialId: assertion.id,
            rpId: publicKey?.rpId ?? window.location.hostname,
            basePrfSalt: begin.basePrfSalt,
            wrappedPrimaryKey: finish.wrappedPrimaryKey ?? null,
            wrappedAnchorKey: finish.wrappedAnchorKey ?? null,
            wrappedKeyEpoch: finish.credentialWrappedKeyEpoch ?? finish.session.wrappedKeyEpoch,
        }
        sessionCredentialWrappedKeyEpoch = finish.credentialWrappedKeyEpoch ?? finish.session.wrappedKeyEpoch
        loginWrappedPrimaryKey = finish.wrappedPrimaryKey ?? null
        loginWrappedAnchorKey = finish.wrappedAnchorKey ?? null
        loginWrappedKeyStale = finish.wrappedKeyStale

        if (finish.wrappedPrimaryKey) {
            // Parse the envelope to determine whether a password is needed
            const envelope = parseWrappedPrimaryKeyEnvelope(finish.wrappedPrimaryKey)
            hasPassword = envelope.passwordRequired
            if (envelope.passwordRequired) {
                return 'password-required'
            }

            // No password required — unwrap immediately with PRF only
            const { wrappingKeyBytes, stretched } = await deriveWrappingKey({
                keyProtection,
                credentialId: sessionCredentialId ?? undefined,
                prfSecret: assertion.prfSecret,
                userId: finish.session.userId,
            })
            sensitiveBuffers.push(wrappingKeyBytes)
            if (stretched) {
                sensitiveBuffers.push(stretched)
            }
            primaryKey = await unwrapPrimaryKey({
                keyProtection,
                credentialId: sessionCredentialId ?? undefined,
                wrapped: finish.wrappedPrimaryKey,
                wrappingKeyBytes,
                userId: finish.session.userId,
            })

            // Also unwrap the hybrid anchor so subsequent credential-add flows can sign attestations
            if (loginWrappedAnchorKey) {
                sessionAnchor = await unwrapAnchorKey({
                    wrapped: loginWrappedAnchorKey,
                    wrappingKeyBytes,
                    userId: finish.session.userId,
                })
            }
            loginWrappedPrimaryKey = null
            loginWrappedAnchorKey = null
        } else {
            hasPassword = false
        }

        return 'authenticated'
    } finally {
        unownedPrf?.fill(0)
        for (const buffer of sensitiveBuffers) {
            buffer.fill(0)
        }
    }
}

async function unlockWithPassword(password: string) {
    const sensitiveBuffers: Uint8Array[] = []
    try {
        const wrappedPrimaryKey = loginWrappedPrimaryKey
        const wrappedAnchorKey = loginWrappedAnchorKey

        if (!wrappedPrimaryKey) {
            throw new Error('Password unlock is not active')
        }
        if ((keyProtection === 'prf' && !prfSecret) || !session) {
            throw new Error('Missing local key material')
        }

        // Note: we are not trimming or otherwise normalizing the password as we must accept it as-is to ensure consistent key derivation
        if (password === '') {
            throw new Error('Password is required')
        }

        // Parse Argon2id params from the wrapped-key envelope
        const envelope = parseWrappedPrimaryKeyEnvelope(wrappedPrimaryKey)
        if (!envelope.argon2id) {
            throw new Error('Wrapped key envelope is missing Argon2id parameters')
        }

        const argon2idSalt = base64UrlToBytes(envelope.argon2id.salt)
        const envelopeArgon2idCost: Argon2idCost = {
            m: envelope.argon2id.m,
            t: envelope.argon2id.t,
            p: envelope.argon2id.p,
        }

        // Derive the wrapping key using Argon2id-stretched password as HKDF salt
        const { wrappingKeyBytes, stretched } = await deriveWrappingKey({
            keyProtection,
            credentialId: sessionCredentialId ?? undefined,
            prfSecret,
            userId: session.userId,
            password,
            argon2idSalt,
            argon2idCost: envelopeArgon2idCost,
        })
        sensitiveBuffers.push(wrappingKeyBytes)
        if (stretched) {
            sensitiveBuffers.push(stretched)
        }

        // Unwrap — success proves the password is correct (replaces canary)
        primaryKey = await unwrapPrimaryKey({
            keyProtection,
            credentialId: sessionCredentialId ?? undefined,
            wrapped: wrappedPrimaryKey,
            wrappingKeyBytes,
            userId: session.userId,
        })

        // Unwrap the hybrid anchor secret too. Without it the session cannot add new credentials.
        if (wrappedAnchorKey) {
            sessionAnchor = await unwrapAnchorKey({
                wrapped: wrappedAnchorKey,
                wrappingKeyBytes,
                userId: session.userId,
            })
        }

        loginWrappedKeyStale = false

        loginWrappedPrimaryKey = null
        loginWrappedAnchorKey = null

        // Retain only until this login action completes; enterReadyView clears it
        sessionPassword = password
    } finally {
        for (const buffer of sensitiveBuffers) {
            buffer.fill(0)
        }
    }
}

async function doLogin() {
    authBusy = true
    authError = null
    pageError = null

    try {
        const outcome = await beginPasskeyLoginStep()
        if (outcome === 'password-required') {
            passwordInput = ''
            uiState = 'password-login'
            return
        }

        enterReadyView()
    } catch (err) {
        clearLocalAuthState()
        authError = err instanceof Error ? err.message : String(err)
        uiState = 'signin'
    } finally {
        authBusy = false
    }
}

async function doRegister() {
    authBusy = true
    authError = null
    pageError = null

    try {
        const begin = await v2RegisterBegin(displayName, keyProtection)
        const cred = await webauthnRegister({
            options: begin.options,
            keyProtection,
        })

        // Stash the credential public key hash so we can sign it into the attestation after password setup
        pendingCredentialPublicKeyHash = cred.publicKeyHash
        await v2RegisterFinish({
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
        })

        const outcome = await beginPasskeyLoginStep()
        if (outcome === 'password-required') {
            passwordInput = ''
            uiState = 'password-login'
            return
        }

        passwordInput = keyProtection === 'bitwarden' ? generateUnlockSecret() : ''
        uiState = 'password-setup'
    } catch (err) {
        clearLocalAuthState()
        if (err instanceof ResponseNotOkError && err.statusCode === 403) {
            signupDisabled = true
            authError = err.message || 'Account creation is disabled on this server.'
            uiState = 'signin'
        } else {
            authError =
                err instanceof PrfUnavailableError
                    ? signupMissingPrfError
                    : err instanceof Error
                      ? err.message
                      : String(err)
        }
    } finally {
        authBusy = false
    }
}

async function doFinishPasswordLogin() {
    authBusy = true
    authError = null
    awaitingReadySessionRefresh = true

    try {
        await unlockWithPassword(passwordInput)
        enterReadyView()
    } catch (err) {
        // Keep only the initial PRF factor while the user retries this login password
        // Partially decrypted primary/anchor material must never survive an error
        primaryKey?.fill(0)
        sessionAnchor?.mldsa87.seed.fill(0)
        primaryKey = null
        sessionAnchor = null
        authError = err instanceof Error ? err.message : 'Incorrect password'
    } finally {
        awaitingReadySessionRefresh = false
        passwordInput = ''
        authBusy = false
    }
}

async function doSkipPassword() {
    passwordInput = ''
    await doSetPassword()
}

async function doSetPassword() {
    const sensitiveBuffers: Uint8Array[] = []

    // This method can be invoked with an empty password too
    if ((keyProtection === 'prf' && !prfSecret) || !session) {
        clearLocalAuthState()
        authError = 'Missing local key material. Sign in again to continue.'
        uiState = 'signin'
        return
    }
    if (!sessionCredentialId || !pendingCredentialPublicKeyHash) {
        clearLocalAuthState()
        authError = 'Missing credential identity for signup. Sign in again to continue.'
        uiState = 'signin'
        return
    }

    authBusy = true
    authError = null

    try {
        // Generate a random primary key and a fresh hybrid anchor (the user's long-lived identity root)
        const pk = await generatePrimaryKey()
        sensitiveBuffers.push(pk)
        const anchor = await generateAnchorKeyPair()
        sensitiveBuffers.push(anchor.mldsa87.seed)

        // Derive wrapping key (with optional Argon2id if password is set)
        const {
            wrappingKeyBytes,
            stretched,
            argon2idSalt,
            argon2idCost: usedCost,
        } = await deriveWrappingKey({
            keyProtection,
            credentialId: sessionCredentialId ?? undefined,
            prfSecret,
            userId: session.userId,
            password: passwordInput || undefined,
            argon2idCost: passwordInput ? argon2idCost : undefined,
        })
        sensitiveBuffers.push(wrappingKeyBytes)
        if (stretched) {
            sensitiveBuffers.push(stretched)
        }

        // Wrap the primary key
        const wrapped = await wrapPrimaryKey({
            keyProtection,
            credentialId: sessionCredentialId ?? undefined,
            primaryKey: pk,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!passwordInput,
            argon2idSalt,
            argon2idCost: usedCost,
        })

        // Wrap the anchor secret blob using the same wrapping key
        const anchorSecret = await serializeAnchorSecret(anchor)
        sensitiveBuffers.push(anchorSecret)
        const wrappedAnchor = await wrapAnchorKey({
            anchorSecret,
            wrappingKeyBytes,
            userId: session.userId,
        })

        // Derive request encryption keys from the primary key
        const { publicKeyJwk } = await deriveRequestEncKeyPair({
            userId: session.userId,
            primaryKey: pk,
        })
        const { encapsulationKeyB64 } = await deriveRequestEncMlkemKeyPair({
            userId: session.userId,
            primaryKey: pk,
        })

        // Canonical wire strings for the anchor pubkeys — signed by the anchor and also stored on the user row.
        const anchorEs384Str = anchorEs384JwkToString(anchor.es384.publicKeyJwk)
        const anchorMldsa87Str = anchorMldsa87PubToString(anchor.mldsa87.publicKey)

        // Sign the pubkey bundle. The CLI pins the anchor and verifies these signatures on every request.
        const bundleSig = await signPubkeyBundleHybrid(anchor, {
            userId: session.userId,
            requestEncEcdhPubkey: JSON.stringify(publicKeyJwk),
            requestEncMlkemPubkey: encapsulationKeyB64,
            anchorEs384Crv: anchor.es384.publicKeyJwk.crv,
            anchorEs384Kty: anchor.es384.publicKeyJwk.kty,
            anchorEs384X: anchor.es384.publicKeyJwk.x,
            anchorEs384Y: anchor.es384.publicKeyJwk.y,
            anchorMldsa87PublicKey: anchorMldsa87Str,
            v: PUBKEY_BUNDLE_VERSION,
        })

        // Sign the first-credential attestation with the fresh anchor.
        const attestSig = await signCredentialAttestationHybrid(anchor, {
            userId: session.userId,
            credentialId: sessionCredentialId,
            credentialPublicKeyHash: pendingCredentialPublicKeyHash,
            wrappedKeyEpoch: 1,
            createdAt: Math.floor(Date.now() / 1000),
        })

        const finalize = await v2FinalizeSignup({
            requestEncEcdhPubkey: publicKeyJwk,
            requestEncMlkemPubkey: encapsulationKeyB64,
            wrappedPrimaryKey: wrapped,
            anchorEs384PublicKey: anchorEs384Str,
            anchorMldsa87PublicKey: anchorMldsa87Str,
            pubkeyBundleSignatureEs384: bundleSig.sigEs384,
            pubkeyBundleSignatureMldsa87: bundleSig.sigMldsa87,
            pubkeyBundleVersion: PUBKEY_BUNDLE_VERSION,
            wrappedAnchorKey: wrappedAnchor,
            attestationPayload: attestSig.canonicalBody,
            attestationSignatureEs384: attestSig.sigEs384,
            attestationSignatureMldsa87: attestSig.sigMldsa87,
        })
        if (finalize.session) {
            session = toSessionResponse(finalize.session)
        }
        session = await v2Session()
        primaryKey = pk
        sessionAnchor = anchor
        if (!wrappedKeyCache) {
            throw new Error('Missing public credential metadata for signup')
        }
        wrappedKeyCache = {
            ...wrappedKeyCache,
            wrappedPrimaryKey: wrapped,
            wrappedAnchorKey: wrappedAnchor,
            wrappedKeyEpoch: 1,
        }
        hasPassword = !!passwordInput
        pendingCredentialPublicKeyHash = null

        // enterReadyView clears this temporary signup password
        sessionPassword = passwordInput || null
        loginWrappedPrimaryKey = null
        loginWrappedAnchorKey = null
        enterReadyView()
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
    } finally {
        for (const buffer of sensitiveBuffers) {
            buffer.fill(0)
        }
        awaitingReadySessionRefresh = false
        passwordInput = ''
        authBusy = false
    }
}

async function doLogout() {
    void teardownListStream()
    try {
        await v2Logout()
    } catch {
        // Ignore logout failures and still clear the local session state.
    }

    clearLocalAuthState()
    items = {}
    passwordInput = ''
    authError = null
    uiState = 'signin'
}

const parseAllowedIpsInput = (raw: string) =>
    raw
        .split(/[\n,]/)
        .map((entry) => entry.trim())
        .filter((entry) => entry !== '')

async function doUpdateAllowedIps() {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2SetAllowedIPs(parseAllowedIpsInput(allowedIpsText))
        if (session) {
            session = { ...session, allowedIps: res.allowedIps }
        }
        allowedIpsText = res.allowedIps.join('\n')
        settingsSuccess = res.allowedIps.length === 0 ? 'Allowed IP restrictions removed' : 'Allowed IPs updated'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doRegenerateRequestKey() {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2RegenerateRequestKey()
        if (session) {
            session = { ...session, requestKey: res.requestKey }
        }
        settingsSuccess = 'Request key regenerated.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doSetRequestAuthMethods(methods: V2RequestAuthMethods) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2SetRequestAuthMethods(methods)
        if (session) {
            session = {
                ...session,
                requestKeyEnabled: res.requestKeyEnabled,
                requestOidcEnabled: res.requestOidcEnabled,
            }
        }
        settingsSuccess = 'Authentication methods updated'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doAddRequestOIDCIssuer(issuer: {
    displayName: string
    issuer: string
    audience: string
    subject: string
    jwksUrl: string
}): Promise<boolean> {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2AddRequestOIDCIssuer(issuer)
        if (session) {
            session = { ...session, requestOidcIssuers: res.requestOidcIssuers }
        }
        settingsSuccess = 'OIDC issuer added'
        return true
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
        return false
    } finally {
        settingsBusy = false
    }
}

async function doDeleteRequestOIDCIssuer(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2DeleteRequestOIDCIssuer(id)
        if (session) {
            session = { ...session, requestOidcIssuers: res.requestOidcIssuers }
        }
        settingsSuccess = 'OIDC issuer removed'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doLoadCredentials() {
    try {
        credentials = (await v2ListCredentials()) ?? []
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    }
}

async function doLoadSigningKeys() {
    try {
        signingKeys = (await v2ListSigningKeys()) ?? []
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    }
}

async function doDeriveSigningKey(keyLabel: string, algorithm: string): Promise<DerivedSigningKey> {
    return await withFreshLocalKeys(() => doDeriveSigningKeyUnlocked(keyLabel, algorithm))
}

async function doDeriveSigningKeyUnlocked(keyLabel: string, algorithm: string): Promise<DerivedSigningKey> {
    if (!session || !primaryKey) {
        throw new Error('Missing local key material')
    }

    const { publicJwk } = await deriveSigningKeyPair({
        userId: session.userId,
        keyLabel,
        algorithm,
        primaryKey,
    })
    const [id, pem] = await Promise.all([computeSigningKeyThumbprint(publicJwk), signingJwkToPem(publicJwk)])
    const sshPublicKey =
        algorithm === 'Ed25519ph' ? '' : signingJwkToSshPublicKey(publicJwk, `${keyLabel}-${algorithm}`)

    // Attempt to register the derived key as unpublished
    // If a row already exists for this (algorithm, keyLabel) the server returns 409 and we treat that as a no-op since the caller just needs the derived material returned
    try {
        await v2CreateSigningKey({
            algorithm,
            keyLabel,
            jwk: publicJwk,
            pem,
            published: false,
        })
    } catch (err) {
        if (!(err instanceof ResponseNotOkError) || err.statusCode !== 409) {
            throw err
        }
    }
    await doLoadSigningKeys()

    return { keyLabel, algorithm, jwk: publicJwk, pem, sshPublicKey, id }
}

async function doPublishSigningKey(derived: DerivedSigningKey): Promise<void> {
    settingsBusy = true
    settingsError = null
    try {
        await withFreshLocalKeys(() => doPublishSigningKeyUnlocked(derived))
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doPublishSigningKeyUnlocked(derived: DerivedSigningKey) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        if (!sessionAnchor || !session) {
            throw new Error('Anchor key is not available — please sign in again to publish a signing key.')
        }

        // The publication proof binds the canonical body the server stores to the anchor pinned at registration
        // We always sign at publish time (and on re-publish if the row has no stored proof), so the server can verify the binding without trusting the browser
        const known = signingKeys.find((k) => k.id === derived.id)
        const needsFreshProof = !known || !known.hasProof

        let proof:
            | { publicationPayload: string; publicationSignatureEs384: string; publicationSignatureMldsa87: string }
            | undefined
        if (needsFreshProof) {
            const signed = await signSigningKeyPublicationHybrid(sessionAnchor, {
                userId: session.userId,
                algorithm: derived.algorithm,
                keyLabel: derived.keyLabel,
                keyId: derived.id,
                wrappedKeyEpoch: session.wrappedKeyEpoch,
                createdAt: Math.floor(Date.now() / 1000),
                v: SIGNING_KEY_PUBLICATION_VERSION,
            })
            proof = {
                publicationPayload: signed.canonicalBody,
                publicationSignatureEs384: signed.sigEs384,
                publicationSignatureMldsa87: signed.sigMldsa87,
            }
        }

        if (known) {
            // Existing row: send proof only when it is missing one — otherwise the toggle is a flag flip
            await v2SetSigningKeyPublished(derived.id, true, proof)
        } else {
            await v2CreateSigningKey({
                algorithm: derived.algorithm,
                keyLabel: derived.keyLabel,
                jwk: derived.jwk,
                pem: derived.pem,
                published: true,
                proof,
            })
        }
        await doLoadSigningKeys()
        settingsSuccess = `Signing key "${derived.keyLabel}" published.`
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doUnpublishSigningKey(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2SetSigningKeyPublished(id, false)
        await doLoadSigningKeys()
        settingsSuccess = 'Signing key unpublished.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doDeleteSigningKey(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2DeleteSigningKey(id)
        await doLoadSigningKeys()
        settingsSuccess = 'Signing key deleted.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doUpdateDisplayName(name: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2UpdateDisplayName(name)
        if (session) {
            session = { ...session, displayName: res.displayName }
        }
        settingsSuccess = 'Display name updated.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doAddPasskey(name: string, newMode: 'prf' | 'bitwarden', newSecret: string): Promise<void> {
    settingsBusy = true
    settingsError = null
    try {
        await withFreshLocalKeys(
            (grant) => doAddPasskeyUnlocked(name, newMode, newSecret, grant),
            undefined,
            'add-credential'
        )
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doAddPasskeyUnlocked(name: string, newMode: 'prf' | 'bitwarden', newSecret: string, grant: string) {
    const sensitiveBuffers: Uint8Array[] = []

    if (!session || !primaryKey) {
        settingsError = 'Missing local key material'
        return
    }
    if (!sessionAnchor) {
        settingsError = 'Missing anchor secret; sign in again and retry.'
        return
    }

    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const begin = await v2AddCredentialBegin(name, newMode, grant)
        const cred = await webauthnRegister({
            options: begin.options,
            keyProtection: newMode,
        })

        // The new credential has its own unique PRF secret, so we must perform a PRF assertion with the newly created credential to derive its wrapping key
        // Use a client-generated random challenge since this ceremony is only used to evaluate PRF locally and is not sent back to the server
        const prfChallenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
        const prfAssertion =
            newMode === 'prf'
                ? await webauthnLoginWithPrf({
                      challenge: prfChallenge,
                      prfSalt: base64UrlToBytes(begin.basePrfSalt),
                      options: {
                          publicKey: {
                              allowCredentials: [{ type: 'public-key', id: cred.id }],
                              userVerification: 'required',
                          },
                      },
                  })
                : undefined
        if (prfAssertion?.prfSecret) {
            sensitiveBuffers.push(prfAssertion.prfSecret)
        }
        if (newMode === 'prf' && (!prfAssertion?.prfSecret || prfAssertion.prfSecret.length === 0)) {
            throw new Error('Authenticator did not return PRF output for the new credential')
        }

        // Wrap the new credential using the password supplied for this action
        const password =
            newMode === 'bitwarden' ? newSecret : keyProtection === 'prf' ? (sessionPassword ?? undefined) : undefined
        const {
            wrappingKeyBytes,
            stretched,
            argon2idSalt,
            argon2idCost: usedCost,
        } = await deriveWrappingKey({
            keyProtection: newMode,
            credentialId: cred.id,
            prfSecret: prfAssertion?.prfSecret,
            userId: session.userId,
            password,
            argon2idCost: password ? argon2idCost : undefined,
        })
        sensitiveBuffers.push(wrappingKeyBytes)
        if (stretched) {
            sensitiveBuffers.push(stretched)
        }

        const wrapped = await wrapPrimaryKey({
            keyProtection: newMode,
            credentialId: cred.id,
            primaryKey,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!password,
            argon2idSalt,
            argon2idCost: usedCost,
        })

        // Wrap a copy of the anchor secret with the new credential's wrapping key so the user can sign in with it later.
        const anchorSecret = await serializeAnchorSecret(sessionAnchor)
        sensitiveBuffers.push(anchorSecret)
        const wrappedAnchor = await wrapAnchorKey({
            anchorSecret,
            wrappingKeyBytes,
            userId: session.userId,
        })

        // Sign an attestation binding this credential to the user's existing anchor.
        const attestSig = await signCredentialAttestationHybrid(sessionAnchor, {
            userId: session.userId,
            credentialId: cred.id,
            credentialPublicKeyHash: cred.publicKeyHash,
            wrappedKeyEpoch: session.wrappedKeyEpoch,
            createdAt: Math.floor(Date.now() / 1000),
        })

        await v2AddCredentialFinish({
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
            credentialName: name,
            wrappedPrimaryKey: wrapped,
            wrappedAnchorKey: wrappedAnchor,
            attestationPayload: attestSig.canonicalBody,
            attestationSignatureEs384: attestSig.sigEs384,
            attestationSignatureMldsa87: attestSig.sigMldsa87,
        })
        await doLoadCredentials()
        settingsSuccess = 'Passkey added.'
    } catch (err) {
        settingsError =
            err instanceof PrfUnavailableError
                ? addPasskeyMissingPrfError
                : err instanceof Error
                  ? err.message
                  : String(err)
    } finally {
        for (const buffer of sensitiveBuffers) {
            buffer.fill(0)
        }
        settingsBusy = false
    }
}

async function doRenamePasskey(id: string, name: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2RenameCredential(id, name)
        await doLoadCredentials()
        settingsSuccess = 'Passkey renamed.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doDeletePasskey(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2DeleteCredential(id)
        await doLoadCredentials()
        settingsSuccess = 'Passkey deleted.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doChangePassword(password: string): Promise<void> {
    settingsBusy = true
    settingsError = null
    try {
        await withFreshLocalKeys((grant) => doChangePasswordUnlocked(password, grant), undefined, 'update-wrapped-key')
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doChangePasswordUnlocked(password: string, grant: string) {
    const sensitiveBuffers: Uint8Array[] = []

    if ((keyProtection === 'prf' && !prfSecret) || !session || !primaryKey || !sessionCredentialId || !sessionAnchor) {
        settingsError = 'Missing local key material'
        return
    }

    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const {
            wrappingKeyBytes,
            stretched,
            argon2idSalt,
            argon2idCost: usedCost,
        } = await deriveWrappingKey({
            keyProtection,
            credentialId: sessionCredentialId ?? undefined,
            prfSecret,
            userId: session.userId,
            password: password || undefined,
            argon2idCost: password ? argon2idCost : undefined,
        })
        sensitiveBuffers.push(wrappingKeyBytes)
        if (stretched) {
            sensitiveBuffers.push(stretched)
        }

        const wrapped = await wrapPrimaryKey({
            keyProtection,
            credentialId: sessionCredentialId ?? undefined,
            primaryKey,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!password,
            argon2idSalt,
            argon2idCost: usedCost,
        })

        // The wrapped primary key lives on the specific credential that signed us in, not on the user record
        const anchorSecret = await serializeAnchorSecret(sessionAnchor)
        sensitiveBuffers.push(anchorSecret)
        const wrappedAnchor = await wrapAnchorKey({
            anchorSecret,
            wrappingKeyBytes,
            userId: session.userId,
        })

        await v2UpdateWrappedKey(sessionCredentialId, wrapped, wrappedAnchor, true, grant)
        session = await v2Session()
        if (!wrappedKeyCache) {
            throw new Error('Sign in again to refresh the encrypted key wrapper')
        }
        wrappedKeyCache = {
            ...wrappedKeyCache,
            wrappedPrimaryKey: wrapped,
            wrappedAnchorKey: wrappedAnchor,
            wrappedKeyEpoch: session.wrappedKeyEpoch,
        }
        saveWrappedKey(wrappedKeyCache)
        sessionCredentialWrappedKeyEpoch = session.wrappedKeyEpoch
        await doLoadCredentials()
        hasPassword = !!password

        // The action cleanup clears this temporary password
        sessionPassword = password || null
        settingsSuccess = password
            ? 'Password updated for this passkey. Other passkeys will ask to refresh on next use.'
            : 'Password removed for this passkey. Other passkeys will refresh on next use.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        for (const buffer of sensitiveBuffers) {
            buffer.fill(0)
        }
        settingsBusy = false
    }
}

async function doRemovePassword() {
    await doChangePassword('')
}

function startListStream() {
    if (stopStream) {
        return
    }

    let stopped = false
    const streamController = new AbortController()
    const stream = v2ListStream({ signal: streamController.signal })
    stopStream = async () => {
        stopped = true
        stopStream = null
        listConnected = false
        streamController.abort()
        await stream.return(undefined)
    }

    void (async () => {
        listConnected = false
        try {
            for await (const item of stream) {
                if (stopped) {
                    return
                }
                listConnected = true
                if (!item) {
                    continue
                }
                if (item.status === 'removed') {
                    delete items[item.state]
                    items = { ...items }
                    continue
                }
                items = {
                    ...items,
                    [item.state]: item,
                }
            }
        } catch (err) {
            if (stopped) {
                return
            }

            if (err instanceof ResponseNotOkError && err.statusCode === 401) {
                clearLocalAuthState()
                items = {}
                authError = 'Session expired. Sign in again.'
                uiState = 'signin'
                return
            }
            if (err instanceof ResponseNotOkError && err.statusCode === 403 && awaitingReadySessionRefresh) {
                return
            }
            pageError = err instanceof Error ? err.message : String(err)
        } finally {
            if (!stopped) {
                stopStream = null
                listConnected = false
                if (uiState === 'ready') {
                    setTimeout(() => {
                        if (uiState === 'ready' && !stopStream) {
                            startListStream()
                        }
                    }, 500)
                }
            }
        }
    })()
}

function removeItem(state: string) {
    delete items[state]
    items = { ...items }
}

function sortedItems() {
    return Object.values(items).sort((a, b) => a.date - b.date)
}
</script>

{#if passwordPrompt}
    <FreshPasswordPrompt {keyProtection} onAnswer={answerPasswordPrompt} />
{/if}

<div class="min-h-screen">
    {#if serverVersion}
        <UpdateAvailable clientVersion={appVersion} onReload={reloadForUpdate} {serverVersion} />
    {:else if uiState === 'ready'}
        <ReadyView
            {keyProtection}
            allowedIpsText={allowedIpsText}
            {credentials}
            displayName={session?.displayName ?? ''}
            {hasPassword}
            listConnected={listConnected}
            onAddPasskey={doAddPasskey}
            onAllowedIpsTextInput={(value) => {
                allowedIpsText = value
            }}
            onChangePassword={doChangePassword}
            onDeletePasskey={doDeletePasskey}
            onDeleteSigningKey={doDeleteSigningKey}
            onDeriveSigningKey={doDeriveSigningKey}
            onLogout={doLogout}
            onPublishSigningKey={doPublishSigningKey}
            onRegenerateRequestKey={doRegenerateRequestKey}
            onSetRequestAuthMethods={doSetRequestAuthMethods}
            onAddRequestOIDCIssuer={doAddRequestOIDCIssuer}
            onDeleteRequestOIDCIssuer={doDeleteRequestOIDCIssuer}
            onRemoveItem={removeItem}
            onRemovePassword={doRemovePassword}
            onRenamePasskey={doRenamePasskey}
            onUnpublishSigningKey={doUnpublishSigningKey}
            onUpdateAllowedIps={doUpdateAllowedIps}
            onUpdateDisplayName={doUpdateDisplayName}
            pageError={pageError}
            pendingItems={sortedItems()}
            withApprovalKey={withApprovalKey}
            requestKey={session?.requestKey ?? ''}
            requestKeyEnabled={session?.requestKeyEnabled ?? true}
            requestOidcEnabled={session?.requestOidcEnabled ?? false}
            requestOidcIssuers={session?.requestOidcIssuers ?? []}
            anchorFingerprint={session?.anchorFingerprint ?? ''}
            sessionLabel={sessionLabel()}
            settingsBusy={settingsBusy}
            settingsError={settingsError}
            settingsErrorHelpHref={settingsErrorHelpHref}
            settingsSuccess={settingsSuccess}
            {signingKeys}
            userId={session?.userId ?? ''}
        />
    {:else if uiState === 'signup' || uiState === 'password-setup'}
        <AuthSetupView
            {keyProtection}
            onKeyProtectionInput={(value) => { keyProtection = value }}
            authBusy={authBusy}
            authError={authError}
            authErrorHelpHref={authErrorHelpHref}
            displayName={displayName}
            onDisplayNameInput={(value) => {
                displayName = value
            }}
            onPasswordInput={(value) => {
                passwordInput = value
            }}
            onRegister={doRegister}
            onReturnToSignIn={returnToSignIn}
            onSetPassword={doSetPassword}
            onSkipPassword={doSkipPassword}
            pageError={pageError}
            passwordInput={passwordInput}
            uiState={uiState}
        />
    {:else}
        <AuthAccessView
            {keyProtection}
            authBusy={authBusy}
            authError={authError}
            loginWrappedPrimaryKey={loginWrappedPrimaryKey}
            onFinishPasswordLogin={doFinishPasswordLogin}
            onLogin={doLogin}
            onOpenSignup={openSignup}
            onPasswordInput={(value) => {
                passwordInput = value
            }}
            onReturnToSignIn={returnToSignIn}
            pageError={pageError}
            passwordInput={passwordInput}
            sessionLabel={sessionLabel()}
            signupDisabled={signupDisabled}
            uiState={uiState}
        />
    {/if}
</div>
