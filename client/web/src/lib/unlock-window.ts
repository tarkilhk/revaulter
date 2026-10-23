export interface UnlockLease {
    unlockLeaseId?: string
    unlockLeaseExpiresAt?: number
}

// The tab owns one short-lived copy; no plaintext or lease is written to browser storage
export function createUnlockWindow(changed: (expiresAt: number) => void) {
    let current: { primaryKey: Uint8Array; leaseId: string; deadline: number; expiresAt: number } | null = null
    let timer: ReturnType<typeof setTimeout> | undefined
    function clear() {
        clearTimeout(timer)
        current?.primaryKey.fill(0)
        current = null
        changed(0)
    }
    function get() {
        if (current && (performance.now() >= current.deadline || Date.now() >= current.expiresAt)) {
            clear()
        }
        return current
    }
    function set(primaryKey: Uint8Array, lease: UnlockLease) {
        clear()
        const expiresAt = (lease.unlockLeaseExpiresAt ?? 0) * 1000
        const remaining = Math.min(expiresAt - Date.now(), 120_000)
        if (!lease.unlockLeaseId || !Number.isFinite(remaining) || remaining <= 0) {
            return
        }
        current = {
            primaryKey: primaryKey.slice(),
            leaseId: lease.unlockLeaseId,
            deadline: performance.now() + remaining,
            expiresAt: Date.now() + remaining,
        }
        timer = setTimeout(clear, remaining)
        changed(current.expiresAt)
    }
    return { get, set, clear }
}
