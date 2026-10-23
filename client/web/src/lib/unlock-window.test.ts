import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createUnlockWindow } from './unlock-window'

beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(100_000)
})
afterEach(() => vi.useRealTimers())

it('owns only a copy and wipes it at the absolute deadline', () => {
    const source = new Uint8Array([1, 2, 3])
    const window = createUnlockWindow(vi.fn())
    window.set(source, { unlockLeaseId: 'dummy', unlockLeaseExpiresAt: 110 })
    const retained = window.get()?.primaryKey
    if (!retained) {
        throw new Error('missing test key')
    }
    source.fill(0)
    expect(Array.from(retained)).toEqual([1, 2, 3])
    vi.advanceTimersByTime(10_000)
    expect(window.get()).toBeNull()
    expect(Array.from(retained)).toEqual([0, 0, 0])
})

it('checks expiry after suspended timers and clears on explicit logout', () => {
    const window = createUnlockWindow(vi.fn())
    window.set(new Uint8Array([9]), { unlockLeaseId: 'dummy', unlockLeaseExpiresAt: 110 })
    const retained = window.get()?.primaryKey
    if (!retained) {
        throw new Error('missing test key')
    }
    vi.setSystemTime(111_000)
    expect(window.get()).toBeNull()
    expect(retained[0]).toBe(0)
    window.set(new Uint8Array([7]), { unlockLeaseId: 'dummy2', unlockLeaseExpiresAt: 120 })
    const second = window.get()?.primaryKey
    if (!second) {
        throw new Error('missing test key')
    }
    window.clear()
    expect(second[0]).toBe(0)
})

it('never extends the server deadline or retains keys without a valid lease', () => {
    const window = createUnlockWindow(vi.fn())
    window.set(new Uint8Array([9]), {})
    expect(window.get()).toBeNull()
    window.set(new Uint8Array([9]), { unlockLeaseId: 'dummy', unlockLeaseExpiresAt: 1000 })
    vi.advanceTimersByTime(120_000)
    expect(window.get()).toBeNull()
})
