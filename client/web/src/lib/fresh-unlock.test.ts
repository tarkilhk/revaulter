import { beforeEach, describe, expect, it, vi } from 'vitest'
import { type WrappedKeyCache, withFreshKeys } from '$lib/fresh-unlock'

const mocks = vi.hoisted(() => ({
    passkey: vi.fn(),
    derive: vi.fn(),
    unwrap: vi.fn(),
    anchor: vi.fn(),
    parse: vi.fn(),
    authorize: vi.fn(),
}))
vi.mock('$lib/webauthn', () => ({ webauthnLoginWithPrf: mocks.passkey }))
vi.mock('$lib/crypto', () => ({
    deriveWrappingKey: mocks.derive,
    unwrapPrimaryKey: mocks.unwrap,
    parseWrappedPrimaryKeyEnvelope: mocks.parse,
}))
vi.mock('$lib/crypto-anchor', () => ({ unwrapAnchorKey: mocks.anchor }))

const cache: WrappedKeyCache = {
    userId: 'user',
    credentialId: 'credential',
    rpId: 'example.com',
    basePrfSalt: 'AQID',
    wrappedPrimaryKey: 'ciphertext-wrapper',
    wrappedAnchorKey: null,
    wrappedKeyEpoch: 1,
}

beforeEach(() => {
    vi.resetAllMocks()
    mocks.authorize.mockResolvedValue(undefined)
    mocks.passkey.mockImplementation(async () => ({
        id: 'credential',
        prfSecret: new Uint8Array(32).fill(7),
        raw: { credential: {} },
    }))
    mocks.derive.mockImplementation(async () => ({
        wrappingKeyBytes: new Uint8Array(32).fill(8),
        stretched: new Uint8Array(32).fill(9),
    }))
    mocks.unwrap.mockImplementation(async () => new Uint8Array(32).fill(10))
    mocks.parse.mockReturnValue({ passwordRequired: false })
})

function unlock(
    use: Parameters<typeof withFreshKeys>[0]['use'],
    getPassword = async (): Promise<string | null> => null
) {
    return withFreshKeys({ cache, authorize: mocks.authorize, getPassword, use })
}

describe('one action per fresh local unlock', () => {
    it('supports six fresh ceremonies without retrieving wrappers and clears each action', async () => {
        const retained: Uint8Array[] = []
        const before = JSON.stringify(cache)
        for (let i = 0; i < 6; i += 1) {
            await unlock(async (keys) => {
                expect(keys.primaryKey[0]).toBe(10)
                retained.push(keys.primaryKey, keys.prfSecret)
            })
            for (const bytes of retained) {
                expect(bytes.every((value) => value === 0)).toBe(true)
            }
        }
        expect(mocks.passkey).toHaveBeenCalledTimes(6)
        expect(mocks.authorize).toHaveBeenCalledTimes(12)
        const calls = mocks.passkey.mock.calls.map(([args]) => args)
        expect(new Set(calls.map((args) => args.challenge)).size).toBe(6)
        for (const args of calls) {
            expect(Buffer.from(args.challenge, 'base64url')).toHaveLength(32)
            expect(args.options.publicKey).toMatchObject({
                rpId: 'example.com',
                userVerification: 'required',
                allowCredentials: [{ id: 'credential' }],
            })
        }
        expect(JSON.stringify(cache)).toBe(before)
        for (const result of mocks.derive.mock.results) {
            const keys = await result.value
            expect(keys.wrappingKeyBytes.every((value: number) => value === 0)).toBe(true)
            expect(keys.stretched.every((value: number) => value === 0)).toBe(true)
        }
    })

    it('clears material when the operation fails', async () => {
        let held: Uint8Array | undefined
        await expect(
            unlock(async (keys) => {
                held = keys.primaryKey
                throw new Error('consumer failed')
            })
        ).rejects.toThrow('consumer failed')
        expect(held?.every((value) => value === 0)).toBe(true)
    })

    it('does not execute after denied verification', async () => {
        mocks.passkey.mockRejectedValue(new Error('NotAllowedError'))
        const use = vi.fn()
        await expect(unlock(use)).rejects.toThrow('NotAllowedError')
        expect(use).not.toHaveBeenCalled()
        expect(mocks.unwrap).not.toHaveBeenCalled()
    })

    it('rejects a different credential and clears the newly obtained PRF bytes', async () => {
        const prf = new Uint8Array(32).fill(7)
        mocks.passkey.mockResolvedValue({ id: 'other-credential', prfSecret: prf })
        const use = vi.fn()
        await expect(unlock(use)).rejects.toThrow('Use the passkey that signed in')
        expect(use).not.toHaveBeenCalled()
        expect(prf.every((value) => value === 0)).toBe(true)
    })

    it('checks session and credential revocation again after the phone ceremony', async () => {
        const prf = new Uint8Array(32).fill(7)
        mocks.passkey.mockResolvedValue({ id: 'credential', prfSecret: prf })
        mocks.authorize.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('revoked'))
        const use = vi.fn()
        await expect(unlock(use)).rejects.toThrow('revoked')
        expect(use).not.toHaveBeenCalled()
        expect(mocks.unwrap).not.toHaveBeenCalled()
        expect(prf.every((value) => value === 0)).toBe(true)
    })

    it('does not use a previous password or key after password cancellation', async () => {
        mocks.parse.mockReturnValue({ passwordRequired: true })
        const use = vi.fn()
        await expect(unlock(use)).rejects.toThrow('Approval canceled')
        expect(use).not.toHaveBeenCalled()
        expect(mocks.unwrap).not.toHaveBeenCalled()
    })
})
