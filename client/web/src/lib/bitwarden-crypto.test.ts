import { describe, expect, it, vi } from 'vitest'
import {
    credentialBindingHash,
    deriveWrappingKey,
    generateUnlockSecret,
    parseWrappedPrimaryKeyEnvelope,
    unwrapPrimaryKey,
    wrapPrimaryKey,
} from '$lib/crypto'
import { bytesToBase64Url } from '$lib/utils'

const cost = { m: 256, t: 1, p: 1 }
const identity = { keyProtection: 'bitwarden' as const, userId: 'user-1', credentialId: 'credential-1' }

async function fixture() {
    const secret = generateUnlockSecret()
    const primaryKey = crypto.getRandomValues(new Uint8Array(32))
    const derived = await deriveWrappingKey({ ...identity, password: secret, argon2idCost: cost })
    const wrapped = await wrapPrimaryKey({ ...identity, primaryKey, passwordRequired: true, ...derived })
    derived.wrappingKeyBytes.fill(0)
    derived.stretched?.fill(0)
    return { secret, primaryKey, wrapped }
}

async function unlock(
    wrapped: string,
    password: string,
    userId = identity.userId,
    credentialId = identity.credentialId
) {
    const envelope = parseWrappedPrimaryKeyEnvelope(wrapped)
    if (!envelope.argon2id) {
        throw new Error('Missing test KDF parameters')
    }
    const salt = Uint8Array.from(Buffer.from(envelope.argon2id.salt, 'base64url'))
    const derived = await deriveWrappingKey({
        ...identity,
        userId,
        credentialId,
        password,
        argon2idCost: cost,
        argon2idSalt: salt,
    })
    try {
        return await unwrapPrimaryKey({
            ...identity,
            userId,
            credentialId,
            wrapped,
            wrappingKeyBytes: derived.wrappingKeyBytes,
        })
    } finally {
        derived.wrappingKeyBytes.fill(0)
        derived.stretched?.fill(0)
    }
}

describe('Bitwarden password-protected key format', () => {
    it('round trips with a 256-bit generated secret and no PRF material', async () => {
        const { secret, primaryKey, wrapped } = await fixture()
        expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/)
        expect(Buffer.from(secret, 'base64url')).toHaveLength(32)
        expect(await unlock(wrapped, secret)).toEqual(primaryKey)
        expect(parseWrappedPrimaryKeyEnvelope(wrapped)).toMatchObject({
            v: 2,
            mode: 'bitwarden',
            credentialHash: await credentialBindingHash(identity.credentialId),
            passwordRequired: true,
        })
        expect(Buffer.from(wrapped, 'base64url').toString()).not.toContain(secret)
    })

    it('fits the unchanged 512-byte limit even with long credential IDs', async () => {
        const credentialId = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(1023)))
        const secret = generateUnlockSecret()
        const derived = await deriveWrappingKey({ ...identity, credentialId, password: secret, argon2idCost: cost })
        const wrapped = await wrapPrimaryKey({
            ...identity,
            credentialId,
            primaryKey: new Uint8Array(32),
            passwordRequired: true,
            ...derived,
        })
        expect(wrapped.length).toBeLessThanOrEqual(512)
        expect(
            await unwrapPrimaryKey({ ...identity, credentialId, wrapped, wrappingKeyBytes: derived.wrappingKeyBytes })
        ).toEqual(new Uint8Array(32))
        derived.wrappingKeyBytes.fill(0)
        derived.stretched?.fill(0)
    })
    it('rejects wrong secrets and substituted owner or credential', async () => {
        const { secret, wrapped } = await fixture()
        await expect(unlock(wrapped, generateUnlockSecret())).rejects.toThrow()
        await expect(unlock(wrapped, secret, 'another-owner')).rejects.toThrow()
        await expect(unlock(wrapped, secret, identity.userId, 'another-credential')).rejects.toThrow()
    })
    it('rejects tampering, unsupported modes and PRF downgrade', async () => {
        const { secret, wrapped } = await fixture()
        const original = parseWrappedPrimaryKeyEnvelope(wrapped)
        for (const changes of [
            { v: 1 },
            { mode: 'prf' },
            { credentialHash: 'other' },
            { passwordRequired: false },
            { ciphertext: 'AAAA' },
        ]) {
            const modified = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ ...original, ...changes })))
            await expect(unlock(modified, secret)).rejects.toThrow()
        }
        await expect(
            unwrapPrimaryKey({ userId: identity.userId, wrapped, wrappingKeyBytes: new Uint8Array(32) })
        ).rejects.toThrow('does not match')
    })
    it('rejects unbounded KDF parameters before expensive work', async () => {
        await expect(
            deriveWrappingKey({
                ...identity,
                password: generateUnlockSecret(),
                argon2idCost: { m: 2 ** 30, t: 999, p: 1 },
            })
        ).rejects.toThrow('Unsupported Argon2id')
        await expect(deriveWrappingKey({ ...identity, password: 'short', argon2idCost: cost })).rejects.toThrow(
            'generated 43-character'
        )
    })
    it('clears stretched material when WebCrypto fails', async () => {
        let stretched: Uint8Array | undefined
        const importKey = vi.spyOn(crypto.subtle, 'importKey').mockImplementationOnce(async (_format, data) => {
            if (data instanceof Uint8Array) {
                stretched = data
            }
            throw new Error('dummy import failure')
        })
        try {
            await expect(
                deriveWrappingKey({ ...identity, password: generateUnlockSecret(), argon2idCost: cost })
            ).rejects.toThrow('dummy import failure')
            expect(stretched).toBeDefined()
            expect(stretched?.every((value) => value === 0)).toBe(true)
        } finally {
            importKey.mockRestore()
        }
    })

    it('keeps PRF material mandatory in PRF mode even with a password', async () => {
        await expect(
            deriveWrappingKey({ userId: 'user', password: generateUnlockSecret(), argon2idCost: cost })
        ).rejects.toThrow('PRF output is required')
    })
})
