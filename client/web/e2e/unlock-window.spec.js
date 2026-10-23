import { expect, test } from '@playwright/test'
import { resetBrowserState, resetState, startCLIRequest, waitForListStream } from './helpers.mjs'
import { createVirtualPasskey } from './passkeys.mjs'

test('Bitwarden login unlocks only this tab for a fixed window with explicit per-request approval', async ({
    page,
    request,
}) => {
    test.setTimeout(60_000)
    await page.setViewportSize({ width: 393, height: 852 })
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
        await page.getByRole('button', { name: 'Sign out' }).click()
        await page.getByRole('button', { name: 'Continue with passkey' }).click()
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('button', { name: 'Unlock local keys' }).click()
        await expect(page.getByText(/Unlocked in this tab for/)).toBeVisible()
        const session = await (await page.request.get('/v2/auth/session')).json()
        const grantRequests = []
        const confirms = []
        page.on('request', (req) => {
            if (req.url().endsWith('/v2/auth/approval/grant')) {
                grantRequests.push(req.postDataJSON())
            }
            if (req.url().endsWith('/v2/api/confirm') && req.postDataJSON().confirm) {
                confirms.push(req.postDataJSON())
            }
        })
        await page.evaluate(() => {
            const get = navigator.credentials.get.bind(navigator.credentials)
            window.unlockCeremonies = 0
            navigator.credentials.get = async (options) => {
                window.unlockCeremonies++
                return get(options)
            }
        })
        await waitForListStream(page)
        for (let index = 0; index < 2; index++) {
            const run = startCLIRequest({
                operation: 'encrypt',
                requestKey: session.requestKey,
                keyLabel: 'window-dummy',
                algorithm: 'A256GCM',
                note: `window request ${index}`,
                value: 'dummy',
            })
            await expect(page.getByText(`window request ${index}`)).toBeVisible()
            expect(confirms).toHaveLength(index)
            await page.getByRole('button', { name: 'Approve', exact: true }).click()
            await run.done
            await expect(page.getByText('All clear')).toBeVisible()
            await expect(page.getByRole('dialog')).toHaveCount(0)
        }
        expect(await page.evaluate(() => window.unlockCeremonies)).toBe(0)
        expect(grantRequests).toHaveLength(2)
        expect(new Set(grantRequests.map((item) => item.state)).size).toBe(2)
        expect(new Set(confirms.map((item) => item.approvalGrant)).size).toBe(2)
        const persisted = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))
        expect(persisted).not.toContain(secret)
        expect(persisted).not.toContain(grantRequests[0].leaseId)
        const tab = await page.context().newPage()
        await tab.goto('/')
        await expect(tab.getByText('This tab is locked.', { exact: false })).toBeVisible()
        await tab.close()
        await page.bringToFront()
        await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
        await expect(page.getByText(/Unlocked in this tab for/)).toBeVisible()
        await page.clock.install()
        await page.route(
            '**/v2/api/request/**',
            async (route) => {
                await page.clock.setSystemTime(new Date((await page.evaluate(() => Date.now())) + 121_000))
                await route.continue()
            },
            { times: 1 }
        )
        const last = startCLIRequest({
            operation: 'encrypt',
            requestKey: session.requestKey,
            keyLabel: 'window-dummy',
            algorithm: 'A256GCM',
            note: 'expired window request',
            value: 'dummy',
        })
        await expect(page.getByText('expired window request')).toBeVisible()
        await page.getByRole('button', { name: 'Approve', exact: true }).click()
        await expect(page.getByText('Unlock expired. Approve again to unlock this tab.', { exact: true })).toBeVisible()
        expect(confirms).toHaveLength(2)
        expect(await page.evaluate(() => window.unlockCeremonies)).toBe(0)
        await page.getByRole('button', { name: 'Retry approval' }).click()
        await expect(page.getByRole('dialog')).toBeVisible()
        expect(await page.evaluate(() => window.unlockCeremonies)).toBe(1)
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('button', { name: 'Continue', exact: true }).click()
        await last.done
        let releaseLogout
        await page.route('**/v2/auth/logout', async (route) => {
            await new Promise((resolve) => {
                releaseLogout = resolve
            })
            await route.continue()
        })
        await page.getByRole('button', { name: 'Sign out' }).click()
        await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Signing out…' })).toBeDisabled()
        await expect(page.getByRole('button', { name: 'Create a new account' })).toBeDisabled()
        expect((await page.evaluate(() => localStorage.getItem('revaulter.encrypted-key-wrapper'))) === null).toBe(true)
        await expect.poll(() => typeof releaseLogout).toBe('function')
        releaseLogout()
        await expect(page.getByRole('button', { name: 'Continue with passkey' })).toBeEnabled()
    } finally {
        await passkey.dispose()
    }
})
