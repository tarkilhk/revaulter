import { expect, test } from '@playwright/test'
import { registerAndReachReady, resetBrowserState, resetState, startCLIRequest, waitForListStream } from './helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('a second action cannot reuse the first approval after verification is canceled', async ({ page }) => {
    test.setTimeout(60_000)
    const auth = await registerAndReachReady(page, 'Fresh approval user')
    let confirmationCount = 0
    page.on('request', (request) => {
        if (request.url().endsWith('/v2/api/confirm') && request.postDataJSON().confirm) {
            confirmationCount += 1
        }
    })
    let pending
    let pendingDone
    try {
        await waitForListStream(page)
        const first = startCLIRequest({
            operation: 'encrypt',
            requestKey: auth.session.requestKey,
            keyLabel: 'dummy',
            algorithm: 'A256GCM',
            note: 'first dummy',
            value: 'dummy data',
        })
        await expect(page.getByText('first dummy')).toBeVisible()
        await page.getByRole('button', { name: 'Verify and confirm' }).click()
        await first.done
        expect(confirmationCount).toBe(1)
        await expect(page.getByText('All clear')).toBeVisible()

        await page.evaluate(() => {
            navigator.credentials.get = async () => {
                throw new DOMException('User canceled verification', 'NotAllowedError')
            }
        })
        pending = startCLIRequest({
            operation: 'encrypt',
            requestKey: auth.session.requestKey,
            keyLabel: 'dummy',
            algorithm: 'A256GCM',
            note: 'second dummy',
            value: 'other dummy data',
        })
        pendingDone = pending.done.catch(() => null)
        await expect(page.getByText('second dummy')).toBeVisible()
        await page.getByRole('button', { name: 'Verify and confirm' }).click()
        await expect(page.getByText('User canceled verification', { exact: true })).toBeVisible()
        expect(confirmationCount).toBe(1)
        await expect(page.getByRole('button', { name: 'Retry verification' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Confirm all', exact: true })).toHaveCount(0)
    } finally {
        if (pending) {
            const response = await page.request.get('/v2/api/list')
            const requests = await response.json()
            for (const request of requests) {
                await page.request.post('/v2/api/confirm', { data: { state: request.state, cancel: true } })
            }
            await pendingDone
        }
        await auth.passkey.dispose()
    }
})

test('six consecutive approvals use six fresh local ceremonies without retrieving server wrappers', async ({
    page,
}) => {
    test.setTimeout(60_000)
    const auth = await registerAndReachReady(page, 'Six fresh approvals')
    let logins = 0
    page.on('request', (request) => {
        if (request.url().endsWith('/v2/auth/login/finish')) {
            logins += 1
        }
    })
    await page.evaluate(() => {
        const original = navigator.credentials.get.bind(navigator.credentials)
        window.freshCeremonies = []
        navigator.credentials.get = async (options) => {
            window.freshCeremonies.push({
                challenge: Array.from(options.publicKey.challenge),
                verification: options.publicKey.userVerification,
            })
            return await original(options)
        }
    })
    try {
        await waitForListStream(page)
        for (let index = 0; index < 6; index += 1) {
            const note = `dummy approval ${index}`
            const run = startCLIRequest({
                operation: 'encrypt',
                requestKey: auth.session.requestKey,
                keyLabel: 'dummy-six',
                algorithm: 'A256GCM',
                note,
                value: 'dummy only',
            })
            await expect(page.getByText(note, { exact: false })).toBeVisible()
            await page.getByRole('button', { name: 'Verify and confirm' }).click()
            await run.done
            await expect(page.getByText('All clear')).toBeVisible()
        }
        const ceremonies = await page.evaluate(() => window.freshCeremonies)
        expect(ceremonies).toHaveLength(6)
        expect(new Set(ceremonies.map((item) => JSON.stringify(item.challenge))).size).toBe(6)
        expect(ceremonies.every((item) => item.verification === 'required')).toBe(true)
        expect(logins).toBe(0)
    } finally {
        await auth.passkey.dispose()
    }
})

test('a revoked credential cannot unlock its cached ciphertext', async ({ page }) => {
    const { addPasskeyThroughSettings, seedPendingRequest } = await import('./helpers.mjs')
    const auth = await registerAndReachReady(page, 'Revoked cache user')
    const manager = auth.passkey.manager
    const second = await manager.addAuthenticator({ active: false })
    try {
        await addPasskeyThroughSettings(page, manager, 'Recovery credential', {
            verifyWith: auth.passkey.authenticatorId,
            enrollWith: second,
        })
        const credentials = await (await page.request.get('/v2/auth/credentials')).json()
        const original = credentials.find((credential) => credential.displayName !== 'Recovery credential')
        const deleted = await page.request.post('/v2/auth/credentials/delete', { data: { id: original.id } })
        expect(deleted.ok()).toBe(true)
        await manager.setActive(auth.passkey.authenticatorId)
        await seedPendingRequest(page.request, {
            userId: auth.session.userId,
            operation: 'decrypt',
            keyLabel: 'revoked-cache',
            algorithm: 'A256GCM',
            requestor: '127.0.0.1',
        })
        await expect(page.getByText('revoked-cache')).toBeVisible()
        await page.getByRole('button', { name: 'Verify and confirm' }).click()
        await expect(
            page.getByText('The session or passkey changed; sign in again before approving', { exact: true })
        ).toBeVisible()
        await expect(page.getByRole('button', { name: 'Retry verification' })).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})
