import { deriveOperationKeyBytes } from '$lib/crypto'
import { performAesGcmOperation, splitAeadCiphertextAndTag } from '$lib/crypto-symmetric'
import { bytesToBase64Url } from '$lib/utils'

export interface OpenBaoEnrollmentStatus {
    enabled: boolean
    requestKeyEnabled: boolean
    enrolled: boolean
    target: string
    updatedAt?: string
}

export interface OpenBaoEnvelope {
    kind: 'revaulter/1'
    algorithm: 'A256GCM'
    keyLabel: 'openbao-unseal'
    value: string
    nonce: string
    tag: string
}

export type EnrollOpenBao = (
    plaintext: Uint8Array,
    signal: AbortSignal,
    progress: (stage: 'encrypting' | 'saving') => void
) => Promise<void>

// The caller owns this buffer and must clear it on completion or departure
export function prepareOpenBaoBundle(target: string, first: string, second: string): Uint8Array {
    const url = new URL(target)
    if (url.protocol !== 'https:' || url.origin !== target) {
        throw new Error('The configured OpenBao target is invalid. Contact the operator.')
    }
    const shares = [first.trim(), second.trim()]
    if (shares.some((share) => !/^[A-Za-z0-9+/]{44}$/.test(share))) {
        throw new Error('Enter two base64 OpenBao shares, each containing 33 bytes.')
    }
    if (shares[0] === shares[1]) {
        throw new Error('Enter two different OpenBao shares.')
    }
    return new TextEncoder().encode(JSON.stringify({ version: 1, target, shares }))
}

export async function encryptOpenBaoBundle(
    plaintext: Uint8Array,
    primaryKey: Uint8Array,
    userId: string,
    signal: AbortSignal
): Promise<OpenBaoEnvelope> {
    let keyBytes: Uint8Array | undefined
    try {
        signal.throwIfAborted()
        keyBytes = await deriveOperationKeyBytes({
            userId,
            primaryKey,
            keyLabel: 'openbao-unseal',
            algorithm: 'A256GCM',
        })
        signal.throwIfAborted()
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const encrypted = await performAesGcmOperation({
            mode: 'encrypt',
            keyBytes,
            value: plaintext,
            nonce,
            aad: new Uint8Array(),
        })
        signal.throwIfAborted()
        const { data, tag } = splitAeadCiphertextAndTag(encrypted)
        return {
            kind: 'revaulter/1',
            algorithm: 'A256GCM',
            keyLabel: 'openbao-unseal',
            value: bytesToBase64Url(data),
            nonce: bytesToBase64Url(nonce),
            tag: bytesToBase64Url(tag),
        }
    } finally {
        keyBytes?.fill(0)
        plaintext.fill(0)
    }
}
