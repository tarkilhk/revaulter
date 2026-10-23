import { deriveWrappingKey, parseWrappedPrimaryKeyEnvelope, unwrapPrimaryKey } from '$lib/crypto'
import { type AnchorKeyPair, unwrapAnchorKey } from '$lib/crypto-anchor'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import { webauthnLoginWithPrf } from '$lib/webauthn'

// Only ciphertext and public credential metadata may survive between actions
export interface WrappedKeyCache {
    userId: string
    credentialId: string
    rpId: string
    basePrfSalt: string
    wrappedPrimaryKey: string | null
    wrappedAnchorKey: string | null
    wrappedKeyEpoch: number
}

export interface FreshKeys {
    primaryKey: Uint8Array
    prfSecret: Uint8Array
    anchor: AnchorKeyPair | null
    password: string | undefined
}

// Every invocation starts a new local, verified WebAuthn ceremony
// There is deliberately no cache or already-unlocked path for plaintext keys
export async function withFreshKeys<T>(args: {
    cache: WrappedKeyCache
    authorize: () => Promise<void>
    getPassword: () => Promise<string | null>
    use: (keys: FreshKeys) => Promise<T>
}): Promise<T> {
    const cache = { ...args.cache }
    if (!cache.wrappedPrimaryKey || !cache.rpId || !cache.credentialId || !cache.basePrfSalt) {
        throw new Error('Sign in again to obtain the encrypted key wrapper')
    }
    let prfSecret: Uint8Array | undefined
    let wrappingKey: Uint8Array | undefined
    let stretched: Uint8Array | undefined
    let primaryKey: Uint8Array | undefined
    let anchor: AnchorKeyPair | null = null
    let password: string | undefined
    try {
        await args.authorize()
        const assertion = await webauthnLoginWithPrf({
            challenge: bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32))),
            prfSalt: base64UrlToBytes(cache.basePrfSalt),
            options: {
                publicKey: {
                    rpId: cache.rpId,
                    allowCredentials: [{ type: 'public-key', id: cache.credentialId }],
                    userVerification: 'required',
                    timeout: 60_000,
                },
            },
        })
        prfSecret = assertion.prfSecret
        if (!prfSecret || assertion.id !== cache.credentialId) {
            throw new Error('Use the passkey that signed in to approve this action')
        }
        const envelope = parseWrappedPrimaryKeyEnvelope(cache.wrappedPrimaryKey)
        if (envelope.passwordRequired) {
            password = (await args.getPassword()) ?? undefined
            if (!password) {
                throw new Error('Approval canceled: password is required')
            }
        }
        // A session or credential can be revoked while the phone prompt is open
        await args.authorize()
        const derived = await deriveWrappingKey({
            prfSecret,
            userId: cache.userId,
            password,
            argon2idSalt: envelope.argon2id ? base64UrlToBytes(envelope.argon2id.salt) : undefined,
            argon2idCost: envelope.argon2id,
        })
        wrappingKey = derived.wrappingKeyBytes
        stretched = derived.stretched
        primaryKey = await unwrapPrimaryKey({
            wrapped: cache.wrappedPrimaryKey,
            wrappingKeyBytes: wrappingKey,
            userId: cache.userId,
        })
        if (cache.wrappedAnchorKey) {
            anchor = await unwrapAnchorKey({
                wrapped: cache.wrappedAnchorKey,
                wrappingKeyBytes: wrappingKey,
                userId: cache.userId,
            })
        }
        return await args.use({ primaryKey, prfSecret, anchor, password })
    } finally {
        primaryKey?.fill(0)
        prfSecret?.fill(0)
        wrappingKey?.fill(0)
        stretched?.fill(0)
        anchor?.mldsa87.seed.fill(0)
        password = undefined
    }
}
