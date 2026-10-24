import { extractCredentialPublicKeyCose } from '$lib/cose-extract'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'

// generatePrfSalt creates a random 32-byte salt for the WebAuthn PRF extension
export function generatePrfSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32))
}

// Returns base64url(SHA-256(raw COSE credential public-key bytes)) for a WebAuthn attestation response
// The hash is taken over the exact CBOR bytes the authenticator wrote, which lets the server re-derive it from its stored COSE credential without any per-algorithm logic
// This matches the algorithm the server and works for any WebAuthn key type, including future post-quantum algorithms
export async function credentialPublicKeyHash(response: AuthenticatorAttestationResponse): Promise<string> {
    const cose = extractCredentialPublicKeyCose(response.attestationObject)
    const digest = await crypto.subtle.digest('SHA-256', asBuf(cose))
    return bytesToBase64Url(new Uint8Array(digest))
}

// cloneAndDecodeWebAuthnOptions clones server options and decodes WebAuthn binary fields from base64url
function cloneAndDecodeWebAuthnOptions<T>(input: T, skipBinaryDecoding = false): T {
    if (input === null || input === undefined) {
        return input
    }

    // Arrays can contain nested credential descriptors whose IDs also require decoding
    if (Array.isArray(input)) {
        return input.map((v) => cloneAndDecodeWebAuthnOptions(v, skipBinaryDecoding)) as T
    }

    if (typeof input === 'object') {
        const out: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
            // WebAuthn JSON represents binary request fields as base64url but the Credentials API requires BufferSource values
            if (
                !skipBinaryDecoding &&
                (k === 'challenge' || k === 'id' || k === 'rawId' || k === 'userHandle') &&
                typeof v === 'string'
            ) {
                out[k] = base64UrlToBytes(v)
                continue
            }
            // Propagate skipBinaryDecoding into rp to preserve domain strings like rp.id and rp.name
            out[k] = cloneAndDecodeWebAuthnOptions(v, skipBinaryDecoding || k === 'rp')
        }
        return out as T
    }

    return input
}

// Only the public PRF capability bit belongs in a server-bound credential
// PRF results and other extension secrets must remain on the client
export function serializeWebAuthnExtensionResults(input: unknown): unknown {
    const extensions = input as { prf?: { enabled?: unknown } } | null
    if (typeof extensions?.prf?.enabled === 'boolean') {
        return { prf: { enabled: extensions.prf.enabled } }
    }
    return {}
}

// serializePublicKeyCredential converts a browser credential to the JSON shape expected by the server
export function serializePublicKeyCredential(cred: PublicKeyCredential) {
    const clientExtensionResults = cred.getClientExtensionResults?.()
    const serializedExtensionResults = clientExtensionResults
        ? serializeWebAuthnExtensionResults(clientExtensionResults)
        : undefined

    // Prefer the browser serializer because it includes response fields added by newer WebAuthn specifications
    const credentialWithToJSON = cred as PublicKeyCredential & { toJSON?: () => unknown }
    if (typeof credentialWithToJSON.toJSON === 'function') {
        const serialized = credentialWithToJSON.toJSON()
        if (serialized !== null && typeof serialized === 'object') {
            return {
                ...(serialized as unknown as Record<string, unknown>),
                // Replace the native extension JSON because some browsers leave PRF output as number arrays or binary objects
                clientExtensionResults: serializedExtensionResults,
            }
        }
    }

    // Older browsers lack toJSON so serialize the stable credential fields manually
    const base = {
        id: cred.id,
        rawId: bytesToBase64Url(new Uint8Array(cred.rawId)),
        type: cred.type,
        clientExtensionResults: serializedExtensionResults,
    }

    if (cred.response instanceof AuthenticatorAttestationResponse) {
        return {
            ...base,
            response: {
                attestationObject: bytesToBase64Url(new Uint8Array(cred.response.attestationObject)),
                clientDataJSON: bytesToBase64Url(new Uint8Array(cred.response.clientDataJSON)),
            },
        }
    }

    if (cred.response instanceof AuthenticatorAssertionResponse) {
        return {
            ...base,
            response: {
                authenticatorData: bytesToBase64Url(new Uint8Array(cred.response.authenticatorData)),
                clientDataJSON: bytesToBase64Url(new Uint8Array(cred.response.clientDataJSON)),
                signature: bytesToBase64Url(new Uint8Array(cred.response.signature)),
                userHandle: cred.response.userHandle
                    ? bytesToBase64Url(new Uint8Array(cred.response.userHandle))
                    : undefined,
            },
        }
    }

    return base
}

export class PrfUnavailableError extends Error {
    constructor() {
        super('PRF is unavailable for this credential')
        this.name = 'PrfUnavailableError'
    }
}

// webauthnRegister creates a passkey and returns its serialized registration data
export async function webauthnRegister(args: {
    options: unknown
    keyProtection?: 'prf' | 'bitwarden'
}): Promise<{ id: string; publicKeyHash: string; signCount: number; raw?: unknown }> {
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        throw new Error('WebAuthn is not available in this browser')
    }
    if (
        !args.options ||
        typeof args.options !== 'object' ||
        !('publicKey' in (args.options as Record<string, unknown>))
    ) {
        throw new Error('WebAuthn registration requires server-provided creation options')
    }

    const creationOptions = (
        cloneAndDecodeWebAuthnOptions(args.options) as PublicKeyCredentialCreationOptionsJSON & {
            publicKey: PublicKeyCredentialCreationOptions
        }
    ).publicKey

    const cred = (await navigator.credentials.create({
        publicKey: creationOptions,
    })) as PublicKeyCredential | null

    if (!cred) {
        throw new Error('WebAuthn registration was canceled')
    }

    const extensionResults = cred.getClientExtensionResults() as {
        prf?: { enabled?: boolean }
    }
    if ((args.keyProtection ?? 'prf') === 'prf' && extensionResults?.prf?.enabled !== true) {
        throw new PrfUnavailableError()
    }

    const resp = cred.response as AuthenticatorAttestationResponse
    const publicKeyHash = await credentialPublicKeyHash(resp)
    return {
        id: cred.id,
        publicKeyHash,
        signCount: 0,
        raw: {
            credential: serializePublicKeyCredential(cred),
            clientDataJSON: bytesToBase64Url(new Uint8Array(resp.clientDataJSON)),
        },
    }
}

// webauthnLoginWithPrf authenticates with a passkey and derives a secret through the PRF extension
export async function webauthnLoginWithPrf(args: {
    challenge: string
    prfSalt?: Uint8Array
    options?: unknown
    requirePrf?: boolean
    evaluatePrf?: boolean
    signal?: AbortSignal
}): Promise<{ id: string; signCount: number; prfSecret?: Uint8Array; raw?: unknown }> {
    const salt = args.prfSalt ?? generatePrfSalt()
    // Copy the view into a standalone ArrayBuffer because WebAuthn accepts BufferSource but the PRF type requires ArrayBuffer
    const saltBuffer = salt.slice().buffer as ArrayBuffer
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        throw new Error('WebAuthn is not available in this browser')
    }

    // Prefer server-provided request policy but retain the fallback for callers that only provide a challenge
    const reqOptions =
        args.options && typeof args.options === 'object' && 'publicKey' in (args.options as Record<string, unknown>)
            ? (cloneAndDecodeWebAuthnOptions(args.options) as { publicKey: PublicKeyCredentialRequestOptions })
                  .publicKey
            : null

    // Override the challenge and PRF input because these values belong to this login attempt
    const effectivePublicKey: PublicKeyCredentialRequestOptions = reqOptions
        ? {
              ...reqOptions,
              userVerification: 'required',
              challenge: asBuf(base64UrlToBytes(args.challenge)),
              extensions: {
                  ...(reqOptions.extensions || {}),
                  prf: {
                      eval: {
                          first: saltBuffer,
                      },
                  },
              } as AuthenticationExtensionsClientInputs,
          }
        : {
              challenge: asBuf(base64UrlToBytes(args.challenge)),
              timeout: 60_000,
              userVerification: 'required',
              extensions: {
                  prf: {
                      eval: {
                          first: saltBuffer,
                      },
                  },
              } as AuthenticationExtensionsClientInputs,
          }

    if (args.evaluatePrf === false) {
        delete effectivePublicKey.extensions
    }

    const assertion = (await navigator.credentials.get({
        publicKey: effectivePublicKey,
        signal: args.signal,
    })) as PublicKeyCredential | null

    if (!assertion) {
        throw new Error('WebAuthn authentication was canceled')
    }

    const resp = assertion.response as AuthenticatorAssertionResponse
    const authenticatorData = new Uint8Array(resp.authenticatorData)
    if (authenticatorData.length < 37 || (authenticatorData[32] & 0x04) === 0) {
        throw new Error('User verification is required')
    }
    const ext = assertion.getClientExtensionResults() as {
        prf?: {
            enabled?: boolean
            results?: { first?: ArrayBuffer }
        }
    }

    const prfBuf = ext?.prf?.results?.first
    if (!prfBuf && args.requirePrf !== false) {
        throw new Error('Authenticator did not return PRF output')
    }

    return {
        id: assertion.id,
        signCount: 0,
        prfSecret: prfBuf ? new Uint8Array(prfBuf) : undefined,
        raw: {
            credential: serializePublicKeyCredential(assertion),
            authenticatorData: bytesToBase64Url(new Uint8Array(resp.authenticatorData)),
            clientDataJSON: bytesToBase64Url(new Uint8Array(resp.clientDataJSON)),
            signature: bytesToBase64Url(new Uint8Array(resp.signature)),
            userHandle: resp.userHandle ? bytesToBase64Url(new Uint8Array(resp.userHandle)) : undefined,
            prfEnabled: ext?.prf?.enabled,
        },
    }
}
