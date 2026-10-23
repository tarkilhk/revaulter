import type { WrappedKeyCache } from './fresh-unlock'

const storageKey = 'revaulter.encrypted-key-wrapper'

// Persist only ciphertext and public credential metadata, never a session or unlocked key
export function saveWrappedKey(cache: WrappedKeyCache | null): void {
    try {
        if (!cache) {
            localStorage.removeItem(storageKey)
            return
        }
        const {
            keyProtection,
            userId,
            credentialId,
            rpId,
            basePrfSalt,
            wrappedPrimaryKey,
            wrappedAnchorKey,
            wrappedKeyEpoch,
        } = cache
        localStorage.setItem(
            storageKey,
            JSON.stringify({
                keyProtection,
                userId,
                credentialId,
                rpId,
                basePrfSalt,
                wrappedPrimaryKey,
                wrappedAnchorKey,
                wrappedKeyEpoch,
            })
        )
    } catch {
        // Browsers that disable storage can still use the current in-memory session
    }
}

export function loadWrappedKey(): WrappedKeyCache | null {
    try {
        const raw = localStorage.getItem(storageKey)
        if (!raw || raw.length > 100_000) {
            return null
        }
        const cache = JSON.parse(raw)
        if (
            !cache ||
            !['prf', 'bitwarden'].includes(cache.keyProtection) ||
            !['userId', 'credentialId', 'rpId', 'basePrfSalt', 'wrappedPrimaryKey', 'wrappedAnchorKey'].every(
                (field) => typeof cache[field] === 'string' && cache[field].length > 0
            ) ||
            !Number.isSafeInteger(cache.wrappedKeyEpoch) ||
            cache.wrappedKeyEpoch < 1
        ) {
            return null
        }
        const {
            keyProtection,
            userId,
            credentialId,
            rpId,
            basePrfSalt,
            wrappedPrimaryKey,
            wrappedAnchorKey,
            wrappedKeyEpoch,
        } = cache
        return {
            keyProtection,
            userId,
            credentialId,
            rpId,
            basePrfSalt,
            wrappedPrimaryKey,
            wrappedAnchorKey,
            wrappedKeyEpoch,
        }
    } catch {
        return null
    }
}
