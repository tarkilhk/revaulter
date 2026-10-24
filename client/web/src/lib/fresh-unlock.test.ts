import { beforeEach, describe, expect, it, vi } from 'vitest'
import { type WrappedKeyCache, withFreshKeys } from '$lib/fresh-unlock'

const mocks = vi.hoisted(() => ({
    begin: vi.fn(),
    finish: vi.fn(),
    passkey: vi.fn(),
    derive: vi.fn(),
    unwrap: vi.fn(),
    anchor: vi.fn(),
    parse: vi.fn(),
    authorize: vi.fn(),
}))
vi.mock('$lib/v2-api', () => ({ v2ApprovalBegin: mocks.begin, v2ApprovalFinish: mocks.finish }))
vi.mock('$lib/webauthn', () => ({ webauthnLoginWithPrf: mocks.passkey }))
vi.mock('$lib/crypto', () => ({
    deriveWrappingKey: mocks.derive,
    unwrapPrimaryKey: mocks.unwrap,
    parseWrappedPrimaryKeyEnvelope: mocks.parse,
}))
vi.mock('$lib/crypto-anchor', () => ({ unwrapAnchorKey: mocks.anchor }))

const cache: WrappedKeyCache = {
    keyProtection: 'prf',
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
    mocks.begin.mockImplementation(async () => ({
        challengeId: crypto.randomUUID(),
        challenge: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'),
        keyProtection: 'prf',
        wrappedKeyEpoch: 1,
        options: {
            publicKey: { rpId: 'example.com', userVerification: 'required', allowCredentials: [{ id: 'credential' }] },
        },
    }))
    mocks.finish.mockResolvedValue({ grantId: 'single-use-grant' })
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
                retained.push(keys.primaryKey)
                if (keys.prfSecret) {
                    retained.push(keys.prfSecret)
                }
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
        mocks.passkey.mockResolvedValue({ id: 'credential', prfSecret: prf, raw: { credential: {} } })
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

describe('explicit Bitwarden approval', () => {
    it('requires server verification before decrypting and never sends the unlock secret', async () => {
        const secret = 'dummy-local-unlock-secret'
        mocks.begin.mockResolvedValue({
            challengeId: 'challenge',
            challenge: 'AQID',
            keyProtection: 'bitwarden',
            wrappedKeyEpoch: 1,
            options: {},
        })
        mocks.passkey.mockResolvedValue({ id: 'credential', raw: { credential: { id: 'credential' } } })
        mocks.parse.mockReturnValue({ passwordRequired: true })
        await withFreshKeys({
            cache: { ...cache, keyProtection: 'bitwarden' },
            requestState: 'request-1',
            authorize: mocks.authorize,
            getPassword: async () => secret,
            use: async (keys) => {
                expect(keys.approvalGrant).toBe('single-use-grant')
            },
        })
        expect(mocks.begin).toHaveBeenCalledWith('credential', 'request-1', undefined)
        expect(mocks.finish).toHaveBeenCalledWith('challenge', { id: 'credential' })
        expect(JSON.stringify([mocks.begin.mock.calls, mocks.finish.mock.calls])).not.toContain(secret)
        expect(mocks.finish.mock.invocationCallOrder[0]).toBeLessThan(mocks.unwrap.mock.invocationCallOrder[0])
    })
    it('fails closed on a server mode mismatch', async () => {
        const use = vi.fn()
        await expect(
            withFreshKeys({
                cache: { ...cache, keyProtection: 'bitwarden' },
                authorize: mocks.authorize,
                getPassword: async () => 'secret',
                use,
            })
        ).rejects.toThrow('Credential protection changed')
        expect(use).not.toHaveBeenCalled()
        expect(mocks.passkey).not.toHaveBeenCalled()
    })
    it('does not unwrap after failed server verification', async () => {
        mocks.finish.mockRejectedValue(new Error('UV verification failed'))
        await expect(unlock(vi.fn())).rejects.toThrow('UV verification failed')
        expect(mocks.unwrap).not.toHaveBeenCalled()
    })
})

describe('enrollment departure', () => {
    it('does not open a late Bitwarden prompt after delayed verification completes', async () => {
        const controller = new AbortController()
        let release: (value: unknown) => void = () => {}
        let entered: () => void = () => {}
        const started = new Promise<void>((resolve) => {
            entered = resolve
        })
        mocks.begin.mockResolvedValue({
            challengeId: 'dummy',
            challenge: 'AQID',
            keyProtection: 'bitwarden',
            wrappedKeyEpoch: 1,
        })
        mocks.parse.mockReturnValue({ passwordRequired: true })
        mocks.passkey.mockImplementation((args) => {
            expect(args.signal).toBe(controller.signal)
            entered()
            return new Promise((resolve) => {
                release = resolve
            })
        })
        const getPassword = vi.fn()
        const use = vi.fn()
        const operation = withFreshKeys({
            cache: { ...cache, keyProtection: 'bitwarden' },
            signal: controller.signal,
            authorize: mocks.authorize,
            getPassword,
            use,
        })
        const rejection = expect(operation).rejects.toThrow()
        await started
        controller.abort()
        release({ id: 'credential', raw: { credential: {} } })
        await rejection
        expect(getPassword).not.toHaveBeenCalled()
        expect(mocks.finish).not.toHaveBeenCalled()
        expect(mocks.unwrap).not.toHaveBeenCalled()
        expect(use).not.toHaveBeenCalled()
    })
})
