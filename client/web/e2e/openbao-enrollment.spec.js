import { expect, test } from '@playwright/test'
import { openSettingsTab, registerAndReachReady, resetBrowserState, resetState } from './helpers.mjs'

const shares = [Buffer.alloc(33, 1).toString('base64'), Buffer.alloc(33, 2).toString('base64')]

async function configureEnrollment(page) {
    const response = await page.request.post('/__e2e__/openbao-enrollment', {
        headers: { 'x-revaulter-e2e-token': process.env.REVAULTER_E2E_TOKEN || 'playwright-e2e-token-fixed' },
        data: { enabled: true },
    })
    expect(response.ok()).toBe(true)
}

async function enterShares(page) {
    await page.getByLabel('Unseal share 1').fill(shares[0])
    await page.getByLabel('Unseal share 2').fill(shares[1])
}

async function assertNoPlaintextStorage(page, observed) {
    const stored = await page.evaluate(async () => {
        const records = [JSON.stringify(localStorage), JSON.stringify(sessionStorage)]
        for (const entry of await indexedDB.databases()) {
            const db = await new Promise((resolve, reject) => {
                const request = indexedDB.open(entry.name)
                request.onsuccess = () => resolve(request.result)
                request.onerror = () => reject(request.error)
            })
            try {
                for (const store of db.objectStoreNames) {
                    const values = await new Promise((resolve, reject) => {
                        const request = db.transaction(store).objectStore(store).getAll()
                        request.onsuccess = () => resolve(request.result)
                        request.onerror = () => reject(request.error)
                    })
                    records.push(JSON.stringify(values))
                }
            } finally {
                db.close()
            }
        }
        for (const name of await caches.keys()) {
            const cache = await caches.open(name)
            for (const request of await cache.keys()) {
                records.push(await (await cache.match(request)).text())
            }
        }
        return records.join('\n')
    })
    for (const share of shares) {
        expect(stored).not.toContain(share)
        expect(observed.join('\n')).not.toContain(share)
    }
}

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('OpenBao browser encryption sends only ciphertext and clears entered shares', async ({ page }, testInfo) => {
    const auth = await registerAndReachReady(page, 'Dummy enrollment owner')
    const observed = []
    const submissions = []
    page.on('console', (message) => observed.push(message.text()))
    page.on('request', (request) => {
        observed.push(request.url(), request.postData() || '')
        if (request.method() === 'PUT' && request.url().endsWith('/v2/auth/openbao-enrollment')) {
            submissions.push(request.postDataJSON())
        }
    })
    try {
        await configureEnrollment(page)
        let releaseLoad
        const loadHeld = new Promise((resolve) => {
            releaseLoad = resolve
        })
        await page.route('**/v2/auth/openbao-enrollment', async (route) => {
            if (route.request().method() === 'GET') {
                await loadHeld
            }
            await route.continue()
        })
        await openSettingsTab(page, 'OpenBao')
        await expect(page.getByText('Loading enrollment…')).toBeVisible()
        await page.screenshot({ path: testInfo.outputPath('openbao-loading.png') })
        releaseLoad()
        await expect(page.getByText('No shares enrolled', { exact: true })).toBeVisible()
        await page.screenshot({ path: testInfo.outputPath('openbao-desktop.png') })
        await page.setViewportSize({ width: 390, height: 844 })
        await page.screenshot({ path: testInfo.outputPath('openbao-mobile.png') })
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
        await enterShares(page)
        await expect(page.getByLabel('Unseal share 1')).toHaveAttribute('type', 'password')
        await expect(page.getByLabel('Unseal share 1')).toHaveAttribute('autocomplete', 'off')
        let releaseSave
        const saveHeld = new Promise((resolve) => {
            releaseSave = resolve
        })
        await page.unroute('**/v2/auth/openbao-enrollment')
        await page.route('**/v2/auth/openbao-enrollment', async (route) => {
            if (route.request().method() === 'PUT') {
                await saveHeld
            }
            await route.continue()
        })
        await page.getByRole('button', { name: 'Encrypt and enroll', exact: true }).click()
        await expect(page.getByText('Saving encrypted enrollment…')).toBeVisible()
        await expect(page.getByLabel('Unseal share 1')).toHaveValue('')
        await expect(page.getByLabel('Unseal share 2')).toHaveValue('')
        await assertNoPlaintextStorage(page, observed)
        releaseSave()
        await expect(page.getByText('Enrollment saved.', { exact: false })).toBeVisible()
        expect(submissions).toHaveLength(1)
        expect(Object.keys(submissions[0]).sort()).toEqual(['approvalGrant', 'envelope'])
        expect(submissions[0].envelope).toMatchObject({
            kind: 'revaulter/1',
            algorithm: 'A256GCM',
            keyLabel: 'openbao-unseal',
        })
        expect(submissions[0].envelope.value).toMatch(/^[A-Za-z0-9_-]+$/)
        const savedResponse = await page.request.get('/__e2e__/openbao-enrollment', {
            headers: { 'x-revaulter-e2e-token': process.env.REVAULTER_E2E_TOKEN || 'playwright-e2e-token-fixed' },
        })
        expect(savedResponse.ok()).toBe(true)
        const saved = await savedResponse.json()
        expect(saved.envelope).toEqual(submissions[0].envelope)
        expect(saved.userId).toBe(auth.session.userId)
        expect(saved.requestKey).toBeTruthy()
        for (const share of shares) {
            expect(JSON.stringify(saved)).not.toContain(share)
        }
        await page.screenshot({ path: testInfo.outputPath('openbao-success-mobile.png') })
        await assertNoPlaintextStorage(page, observed)
    } finally {
        await auth.passkey.dispose()
    }
})

test('OpenBao clears shares on validation, departure, pagehide, failed verification and logout', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Dummy enrollment owner')
    try {
        await configureEnrollment(page)
        await openSettingsTab(page, 'OpenBao')
        await enterShares(page)
        await page.getByLabel('Unseal share 2').fill(shares[0])
        await page.getByRole('button', { name: 'Encrypt and enroll', exact: true }).click()
        await expect(page.getByRole('alert')).toHaveText('Enter two different OpenBao shares.')
        await expect(page.getByLabel('Unseal share 1')).toHaveValue('')
        await enterShares(page)
        await page.locator('nav button', { hasText: 'User' }).click()
        await page.locator('nav button', { hasText: 'OpenBao' }).click()
        await expect(page.getByLabel('Unseal share 1')).toHaveValue('')
        await enterShares(page)
        await page.getByRole('button', { name: 'Close settings' }).click()
        await openSettingsTab(page, 'OpenBao')
        await expect(page.getByLabel('Unseal share 1')).toHaveValue('')
        await enterShares(page)
        await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')))
        await expect(page.getByLabel('Unseal share 1')).toHaveValue('')
        await page.getByRole('button', { name: 'Close settings' }).click()
        await openSettingsTab(page, 'OpenBao')
        await enterShares(page)
        await page.evaluate(() => {
            navigator.credentials.get = async () => {
                throw new DOMException('Canceled', 'NotAllowedError')
            }
        })
        await page.getByRole('button', { name: 'Encrypt and enroll', exact: true }).click()
        await expect(page.getByRole('alert')).toContainText('Enrollment was not confirmed')
        await expect(page.getByLabel('Unseal share 1')).toHaveCount(0)
        await page.getByRole('button', { name: 'Reload status' }).click()
        await expect(page.getByText('No shares enrolled', { exact: true })).toBeVisible()
        await enterShares(page)
        await page.getByRole('button', { name: 'Close settings' }).click()
        await page.getByRole('button', { name: 'Sign out', exact: true }).click()
        await expect(page.getByLabel('Unseal share 1')).toHaveCount(0)
        await assertNoPlaintextStorage(page, [])
    } finally {
        await auth.passkey.dispose()
    }
})

test('OpenBao load errors offer retry and closing during verification prevents upload', async ({ page }, testInfo) => {
    const auth = await registerAndReachReady(page, 'Dummy enrollment owner')
    let uploads = 0
    page.on('request', (request) => {
        if (request.method() === 'PUT' && request.url().endsWith('/v2/auth/openbao-enrollment')) {
            uploads += 1
        }
    })
    try {
        await configureEnrollment(page)
        await page.route('**/v2/auth/openbao-enrollment', (route) => route.fulfill({ status: 503, body: '{}' }))
        await openSettingsTab(page, 'OpenBao')
        await expect(page.getByRole('alert')).toContainText('Could not load OpenBao enrollment')
        await page.screenshot({ path: testInfo.outputPath('openbao-load-error.png') })
        await page.unroute('**/v2/auth/openbao-enrollment')
        await page.getByRole('button', { name: 'Reload status' }).click()
        await enterShares(page)
        let releaseApproval
        const held = new Promise((resolve) => {
            releaseApproval = resolve
        })
        await page.route('**/v2/auth/approval/begin', async (route) => {
            await held
            await route.continue()
        })
        await page.getByRole('button', { name: 'Encrypt and enroll', exact: true }).click()
        await expect(page.getByText('Verify with your passkey to continue…')).toBeVisible()
        await expect(page.getByLabel('Unseal share 1')).toHaveValue('')
        await page.getByRole('button', { name: 'Close settings' }).click()
        const finished = page.waitForResponse('**/v2/auth/approval/begin')
        releaseApproval()
        await finished
        await openSettingsTab(page, 'OpenBao')
        await expect(page.getByText('No shares enrolled', { exact: true })).toBeVisible()
        expect(uploads).toBe(0)
        await expect(page.getByLabel('Unseal share 1')).toHaveValue('')
    } finally {
        await auth.passkey.dispose()
    }
})

test('OpenBao requires the account request key before collecting shares', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Dummy enrollment account')
    try {
        await configureEnrollment(page)
        await openSettingsTab(page, 'Request auth')
        const toggle = page.getByRole('checkbox', { name: /^Request key/ })
        await toggle.uncheck()
        await expect(page.getByRole('button', { name: 'Regenerate Regenerate' })).toBeHidden()
        await page.locator('nav button', { hasText: 'OpenBao' }).click()
        await expect(
            page.getByText(
                'Enable Request key in Settings → Request auth to let OpenBao send approval requests to this account.'
            )
        ).toBeVisible()
        await expect(page.getByLabel('Unseal share 1')).toHaveCount(0)
        await expect(page.getByRole('button', { name: 'Encrypt and enroll', exact: true })).toHaveCount(0)
        await page.locator('nav button', { hasText: 'Request auth' }).click()
        await expect(toggle).not.toBeChecked()
        await toggle.check()
        await expect(page.getByRole('button', { name: 'Regenerate Regenerate' })).toBeVisible()
        await page.locator('nav button', { hasText: 'OpenBao' }).click()
        await expect(page.getByLabel('Unseal share 1')).toBeVisible()
        await expect(page.getByLabel('Unseal share 2')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})
