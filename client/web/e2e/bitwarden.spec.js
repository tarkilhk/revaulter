import { expect, test } from '@playwright/test'
import {
    openSettingsTab,
    readSession,
    registerThroughUI,
    registerWithManager,
    resetBrowserState,
    resetState,
    signInWithAuthenticator,
    signOutThroughUI,
    skipPasswordSetup,
    startCLIRequest,
    waitForListStream,
} from './helpers.mjs'
import { createVirtualPasskey, createVirtualPasskeyManager } from './passkeys.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('explicit Bitwarden signup, fresh ordinary passkeys, local secret and cancellation', async ({ page }) => {
    test.setTimeout(90_000)
    await page.setViewportSize({ width: 393, height: 852 })
    const passkey = await createVirtualPasskey(page, { hasPrf: false })
    const sent = []
    page.on('request', (request) => {
        if (request.method() === 'POST') {
            sent.push({ url: request.url(), body: request.postData() ?? '' })
        }
    })
    let pending
    let pendingDone
    try {
        await page.goto('/')
        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByLabel('Bitwarden passkey and unlock secret', { exact: true }).check()
        await page.getByLabel('Display name (optional)').fill('Dummy Bitwarden user')
        await page.getByRole('button', { name: 'Create account with passkey' }).click()
        await expect(page.getByRole('heading', { name: 'Save your unlock secret' })).toBeVisible()
        const secret = await page.getByLabel('Unlock secret', { exact: true }).inputValue()
        expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/)
        await page.getByLabel('I saved this secret in my Revaulter Bitwarden login item.').check()
        await page.getByRole('button', { name: 'Finish setup' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const session = await (await page.request.get('/v2/auth/session')).json()
        await page.reload()
        await waitForListStream(page)
        await page.evaluate(() => {
            const original = navigator.credentials.get.bind(navigator.credentials)
            window.approvalOptions = []
            navigator.credentials.get = async (options) => {
                window.approvalOptions.push({
                    uv: options.publicKey.userVerification,
                    prf: !!options.publicKey.extensions?.prf,
                })
                return original(options)
            }
        })
        const first = startCLIRequest({
            operation: 'encrypt',
            requestKey: session.requestKey,
            keyLabel: 'dummy',
            algorithm: 'A256GCM',
            note: 'Bitwarden first dummy',
            value: 'dummy plaintext',
        })
        await expect(page.getByText('Bitwarden first dummy')).toBeVisible({ timeout: 30_000 })
        await page.getByRole('button', { name: 'Approve' }).click()
        await expect(page.getByRole('dialog')).toBeVisible()
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('button', { name: 'Continue', exact: true }).click()
        await first.done
        await expect(page.getByText('All clear')).toBeVisible()
        expect(await page.evaluate(() => window.approvalOptions)).toEqual([{ uv: 'required', prf: false }])
        expect(sent.some((request) => request.body.includes(secret))).toBe(false)
        const confirmed = sent.filter(
            (request) => request.url.endsWith('/v2/api/confirm') && JSON.parse(request.body).confirm
        )
        expect(confirmed).toHaveLength(1)
        expect(JSON.parse(confirmed[0].body).approvalGrant).toBeTruthy()
        expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain(secret)

        await page.reload()
        await waitForListStream(page)
        await page.evaluate(() => {
            const original = navigator.credentials.get.bind(navigator.credentials)
            window.approvalOptions = []
            navigator.credentials.get = async (options) => {
                window.approvalOptions.push({
                    uv: options.publicKey.userVerification,
                    prf: !!options.publicKey.extensions?.prf,
                })
                return original(options)
            }
        })
        pending = startCLIRequest({
            operation: 'encrypt',
            requestKey: session.requestKey,
            keyLabel: 'dummy',
            algorithm: 'A256GCM',
            note: 'Bitwarden canceled dummy',
            value: 'never approved',
        })
        pendingDone = pending.done.catch(() => null)
        await expect(page.getByText('Bitwarden canceled dummy')).toBeVisible()
        await page.getByRole('button', { name: 'Approve' }).click()
        await expect(page.getByRole('dialog')).toBeVisible()
        expect(await page.getByLabel('Unlock secret', { exact: true }).inputValue()).toBe('')
        await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click()
        await expect(page.getByText('Approval canceled: password is required', { exact: true })).toBeVisible()
        expect(
            sent.filter((request) => request.url.endsWith('/v2/api/confirm') && JSON.parse(request.body).confirm)
        ).toHaveLength(1)
        expect(await page.evaluate(() => window.approvalOptions)).toHaveLength(1)
        // Returning login uses the stored explicit mode, never local registration state
        await page.getByRole('button', { name: 'Sign out' }).click()
        await page.getByRole('button', { name: 'Continue with passkey' }).click()
        await expect(page.getByRole('heading', { name: 'Unlock with Bitwarden' })).toBeVisible()
        await page.getByLabel('Unlock secret', { exact: true }).fill('A'.repeat(43))
        await page.getByRole('button', { name: 'Unlock local keys' }).click()
        await expect(
            page.getByText('Failed to unwrap primary key. The password or passkey may be incorrect.')
        ).toBeVisible()
        expect(await page.getByLabel('Unlock secret', { exact: true }).inputValue()).toBe('')
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('button', { name: 'Unlock local keys' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        expect(sent.some((request) => request.body.includes(secret))).toBe(false)

        await page.getByRole('button', { name: 'Sign out' }).click()
        await page.route('**/v2/auth/login/finish', async (route) => {
            const response = await route.fetch()
            const body = await response.json()
            body.wrappedAnchorKey = 'YmFk'
            await route.fulfill({ response, json: body })
        })
        await page.evaluate(() => {
            const decrypt = crypto.subtle.decrypt.bind(crypto.subtle)
            window.partialLoginBuffers = []
            crypto.subtle.decrypt = async (...args) => {
                const output = await decrypt(...args)
                if (output.byteLength === 32) {
                    window.partialLoginBuffers.push(new Uint8Array(output))
                }
                return output
            }
        })
        await page.getByRole('button', { name: 'Continue with passkey' }).click()
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('button', { name: 'Unlock local keys' }).click()
        await expect.poll(() => page.evaluate(() => window.partialLoginBuffers.length)).toBe(1)
        await expect
            .poll(() =>
                page.evaluate(() => window.partialLoginBuffers.every((buffer) => buffer.every((byte) => byte === 0)))
            )
            .toBe(true)
    } finally {
        if (pending) {
            const requests = await (await page.request.get('/v2/api/list')).json()
            for (const request of requests) {
                await page.request.post('/v2/api/confirm', { data: { state: request.state, cancel: true } })
            }
            await pendingDone
        }
        await passkey.dispose()
    }
})

test('PRF mode never silently accepts a non-PRF credential', async ({ page }) => {
    const passkey = await createVirtualPasskey(page, { hasPrf: false })
    try {
        await page.goto('/')
        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByRole('button', { name: 'Create account with passkey' }).click()
        await expect(page.getByText(/This passkey does not support the PRF extension/)).toBeVisible()
        await expect(page.getByLabel('PRF passkey', { exact: true })).toBeChecked()
        await expect(page.getByRole('heading', { name: 'Save your unlock secret' })).toHaveCount(0)
    } finally {
        await passkey.dispose()
    }
})

test('an existing PRF account adds Bitwarden and both modes decrypt the same primary key', async ({ page }) => {
    test.setTimeout(90_000)
    const manager = await createVirtualPasskeyManager(page)
    try {
        const prfId = await registerWithManager(page, manager, 'Mixed protection dummy')
        await skipPasswordSetup(page)
        const original = await readSession(page)
        const bitwardenId = await manager.addAuthenticator({ hasPrf: false })
        await openSettingsTab(page, 'Passkeys')
        await page.getByRole('button', { name: 'Add passkey' }).click()
        await page.getByLabel('Passkey name (optional)').fill('Bitwarden dummy')
        await page.getByLabel('Key protection', { exact: true }).selectOption('bitwarden')
        await page.getByRole('button', { name: 'Generate unlock secret' }).click()
        const secret = await page.getByLabel('Existing Revaulter unlock secret from Bitwarden').inputValue()
        await page.route('**/v2/auth/credentials/add/begin', async (route) => {
            await manager.setActive(bitwardenId)
            await route.continue()
        })
        await page.getByRole('button', { name: 'Register passkey' }).click()
        await expect(page.getByText('Passkey added.', { exact: true })).toBeVisible()
        await page.unroute('**/v2/auth/credentials/add/begin')
        await page.getByRole('button', { name: 'Close settings' }).click()
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, bitwardenId)
        await expect(page.getByRole('heading', { name: 'Unlock with Bitwarden' })).toBeVisible()
        await page.getByLabel('Unlock secret', { exact: true }).fill(secret)
        await page.getByRole('button', { name: 'Unlock local keys' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const current = await readSession(page)
        expect(current.anchorFingerprint).toBe(original.anchorFingerprint)
        expect(current.userId).toBe(original.userId)
        await waitForListStream(page)
        const encryption = startCLIRequest({
            operation: 'encrypt',
            requestKey: current.requestKey,
            keyLabel: 'mixed',
            algorithm: 'A256GCM',
            note: 'mixed Bitwarden encrypt',
            value: 'shared dummy plaintext',
        })
        await expect(page.getByText('mixed Bitwarden encrypt')).toBeVisible()
        await page.getByRole('button', { name: 'Approve' }).click()
        await expect(page.getByRole('dialog')).toHaveCount(0)
        const encrypted = (await encryption.done).json
        // Add the opposite mode while authenticated with Bitwarden as well
        const addedPrfId = await manager.addAuthenticator({ hasPrf: true })
        await manager.setActive(bitwardenId)
        await openSettingsTab(page, 'Passkeys')
        await page.getByRole('button', { name: 'Add passkey' }).click()
        await page.getByLabel('Passkey name (optional)').fill('Added PRF dummy')
        await page.getByLabel('Key protection', { exact: true }).selectOption('prf')
        await page.route('**/v2/auth/credentials/add/begin', async (route) => {
            await manager.setActive(addedPrfId)
            await route.continue()
        })
        await page.getByRole('button', { name: 'Register passkey' }).click()
        await page
            .getByRole('dialog')
            .filter({ has: page.getByText('Unlock this action', { exact: true }) })
            .getByLabel('Unlock secret', { exact: true })
            .fill(secret)
        await page.getByRole('button', { name: 'Continue', exact: true }).click()
        await expect(page.getByText('Passkey added.', { exact: true })).toBeVisible()
        await page.unroute('**/v2/auth/credentials/add/begin')
        await page.getByRole('button', { name: 'Close settings' }).click()
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, addedPrfId)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        await waitForListStream(page)
        const decryption = startCLIRequest({
            operation: 'decrypt',
            requestKey: current.requestKey,
            keyLabel: 'mixed',
            algorithm: 'A256GCM',
            note: 'mixed PRF decrypt',
            value: encrypted.value,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
            aad: encrypted.additionalData,
        })
        await expect(page.getByText('mixed PRF decrypt')).toBeVisible()
        await page.getByRole('button', { name: 'Approve' }).click()
        expect((await decryption.done).json.decodedValue).toBe('shared dummy plaintext')
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, prfId)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        expect((await readSession(page)).anchorFingerprint).toBe(original.anchorFingerprint)
    } finally {
        await manager.dispose()
    }
})

test('failed server login verification clears the unowned PRF buffer', async ({ page }) => {
    const passkey = await registerThroughUI(page, 'Dummy PRF cleanup')
    try {
        await skipPasswordSetup(page)
        await signOutThroughUI(page)
        await page.evaluate(() => {
            const get = navigator.credentials.get.bind(navigator.credentials)
            navigator.credentials.get = async (options) => {
                const assertion = await get(options)
                window.failedLoginPrf = new Uint8Array(assertion.getClientExtensionResults().prf.results.first)
                return assertion
            }
        })
        await page.route('**/v2/auth/login/finish', (route) =>
            route.fulfill({ status: 403, json: { error: 'Dummy verification failure' } })
        )
        await page.getByRole('button', { name: 'Continue with passkey' }).click()
        await expect(page.getByText('Dummy verification failure', { exact: true })).toBeVisible()
        expect(await page.evaluate(() => window.failedLoginPrf.every((byte) => byte === 0))).toBe(true)
    } finally {
        await passkey.dispose()
    }
})
