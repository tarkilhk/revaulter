import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { loadWrappedKey, saveWrappedKey } from './wrapped-key-storage'

const cache = {
    keyProtection: 'bitwarden' as const,
    userId: 'dummy-owner',
    credentialId: 'dummy-credential',
    rpId: 'localhost',
    basePrfSalt: 'dummy-public-salt',
    wrappedPrimaryKey: 'dummy-ciphertext',
    wrappedAnchorKey: 'dummy-anchor-ciphertext',
    wrappedKeyEpoch: 1,
}
let stored: string | null
beforeEach(() => {
    stored = null
    vi.stubGlobal('localStorage', {
        getItem: () => stored,
        setItem: (_key: string, value: string) => {
            stored = value
        },
        removeItem: () => {
            stored = null
        },
    })
})
afterEach(() => vi.unstubAllGlobals())

it('persists only the explicit ciphertext and public metadata fields', () => {
    const extra = {
        ...cache,
        password: 'not-storable',
        requestKey: 'not-storable',
        primaryKey: 'not-storable',
        approvalGrant: 'not-storable',
    }
    saveWrappedKey(extra)
    expect(stored).not.toContain('not-storable')
    expect(loadWrappedKey()).toEqual(cache)
    saveWrappedKey(null)
    expect(loadWrappedKey()).toBeNull()
})

it.each([
    '{',
    'null',
    JSON.stringify({ ...cache, keyProtection: 'unknown' }),
    JSON.stringify({ ...cache, wrappedKeyEpoch: -1 }),
    JSON.stringify({ ...cache, wrappedPrimaryKey: null }),
    'x'.repeat(100_001),
])('rejects malformed or incomplete cache', (value) => {
    stored = value
    expect(loadWrappedKey()).toBeNull()
})

it('tolerates disabled browser storage without failing an in-memory session', () => {
    vi.stubGlobal('localStorage', {
        getItem: () => {
            throw new Error('blocked')
        },
        setItem: () => {
            throw new Error('blocked')
        },
        removeItem: () => {
            throw new Error('blocked')
        },
    })
    expect(() => saveWrappedKey(cache)).not.toThrow()
    expect(() => saveWrappedKey(null)).not.toThrow()
    expect(loadWrappedKey()).toBeNull()
})
