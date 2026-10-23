import { expect, test } from '@playwright/test'
import { resetBrowserState, resetState, startCLIRequest, waitForListStream } from './helpers.mjs'
import { createVirtualPasskey } from './passkeys.mjs'

test('returning Bitwarden session survives reload without another full login', async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
    const passkey = await createVirtualPasskey(page, { hasPrf: false })
    try {
        await page.goto('/')
        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByLabel('Bitwarden passkey and unlock secret', { exact: true }).check()
        await page.getByRole('button', { name: 'Create account with passkey' }).click()
        const secret = await page.getByLabel('Unlock secret', { exact: true }).inputValue()
        await page.getByLabel('I saved this secret in my Revaulter Bitwarden login item.').check()
        await page.getByRole('button', { name: 'Finish setup' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const before = await (await page.request.get('/v2/auth/session')).json()
        expect(before.authenticated).toBe(true)
        const loginRequests = []
        page.on('request', (req) => {
            if (req.url().includes('/v2/auth/login/')) {
                loginRequests.push(req.url())
            }
        })
        for (let i = 0; i < 5; i++) {
            await page.reload()
            expect((await (await page.request.get('/v2/auth/session')).json()).authenticated).toBe(true)
            await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        }
        const notificationTab = await page.context().newPage()
        await notificationTab.goto('/')
        await expect(notificationTab.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        await notificationTab.close()
        expect(loginRequests).toEqual([])
        await waitForListStream(page)
        const pending = startCLIRequest({
            operation: 'encrypt',
            requestKey: before.requestKey,
            keyLabel: 'dummy',
            algorithm: 'A256GCM',
            note: 'Restored approval',
            value: 'dummy',
        })
        const pendingDone = pending.done.catch(() => null)
        await expect(page.getByText('Restored approval')).toBeVisible()
        const ceremonies = []
        page.on('request', (req) => {
            if (req.url().endsWith('/v2/auth/approval/finish')) {
                ceremonies.push(req.url())
            }
        })
        await page.getByRole('button', { name: 'Verify and confirm' }).click()
        await expect(page.getByRole('dialog')).toBeVisible()
        expect(ceremonies).toHaveLength(1)
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click()
        await page.getByRole('button', { name: 'Retry verification' }).click()
        await expect(page.getByRole('dialog')).toBeVisible()
        expect(ceremonies).toHaveLength(2)
        expect(await page.getByLabel('Unlock secret', { exact: true }).inputValue()).toBe('')
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('button', { name: 'Continue', exact: true }).click()
        expect(await pendingDone).not.toBeNull()
        expect(loginRequests).toEqual([])
        const saved = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))
        expect(saved).not.toContain(secret)
        expect(saved).not.toContain(before.requestKey)
        await page.getByRole('button', { name: 'Sign out' }).click()
        await expect(page.getByRole('button', { name: 'Continue with passkey' })).toBeVisible()
        expect((await page.evaluate(() => localStorage.getItem('revaulter.encrypted-key-wrapper'))) === null).toBe(true)
    } finally {
        await passkey.dispose()
    }
})

test('restoration rejects changed owners, missing credentials, stale epochs and invalid ciphertext', async ({
    page,
    request,
}) => {
    await resetState(request)
    await resetBrowserState(page)
    const passkey = await createVirtualPasskey(page, { hasPrf: false })
    try {
        await page.goto('/')
        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByLabel('Bitwarden passkey and unlock secret', { exact: true }).check()
        await page.getByRole('button', { name: 'Create account with passkey' }).click()
        await page.getByLabel('I saved this secret in my Revaulter Bitwarden login item.').check()
        await page.getByRole('button', { name: 'Finish setup' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const before = await (await page.request.get('/v2/auth/session')).json()
        expect(before.authenticated).toBe(true)
        const original = await page.evaluate(() => localStorage.getItem('revaulter.encrypted-key-wrapper'))
        for (const change of [
            { userId: 'different-owner' },
            { credentialId: 'revoked-credential' },
            { wrappedKeyEpoch: 99 },
            { keyProtection: 'prf' },
            { wrappedPrimaryKey: 'invalid-ciphertext' },
        ]) {
            await page.evaluate(
                ({ original, change }) =>
                    localStorage.setItem(
                        'revaulter.encrypted-key-wrapper',
                        JSON.stringify({ ...JSON.parse(original), ...change })
                    ),
                { original, change }
            )
            await page.reload()
            await expect(page.getByRole('button', { name: 'Continue with passkey' })).toBeVisible()
            await expect(page.getByRole('heading', { name: 'Pending approvals' })).toHaveCount(0)
            expect((await page.evaluate(() => localStorage.getItem('revaulter.encrypted-key-wrapper'))) === null).toBe(
                true
            )
        }
        await page.evaluate((original) => localStorage.setItem('revaulter.encrypted-key-wrapper', original), original)
        await page.context().clearCookies()
        await page.reload()
        await expect(page.getByRole('button', { name: 'Continue with passkey' })).toBeVisible()
        expect((await page.evaluate(() => localStorage.getItem('revaulter.encrypted-key-wrapper'))) === null).toBe(true)
    } finally {
        await passkey.dispose()
    }
})
