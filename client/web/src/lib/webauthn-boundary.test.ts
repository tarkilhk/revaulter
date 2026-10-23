import { afterEach, describe, expect, it, vi } from 'vitest'
import { v2LoginFinish } from '$lib/v2-api'
import { webauthnLoginWithPrf } from '$lib/webauthn'

class AssertionResponse {
    authenticatorData = new Uint8Array(37).buffer
    clientDataJSON = new Uint8Array([1]).buffer
    signature = new Uint8Array([2]).buffer
    userHandle = null
}

afterEach(() => vi.unstubAllGlobals())

describe('client-only PRF boundary', () => {
    function setup(verified = true) {
        const response = new AssertionResponse()
        new Uint8Array(response.authenticatorData)[32] = verified ? 0x05 : 0x01
        const secret = new Uint8Array(32).fill(0xa7)
        const get = vi.fn().mockResolvedValue({
            id: 'dummy-credential',
            rawId: new Uint8Array([1]).buffer,
            type: 'public-key',
            response,
            toJSON: () => ({ clientExtensionResults: { prf: { results: { first: 'unsafe-native-json' } } } }),
            getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: secret.buffer } } }),
        })
        vi.stubGlobal('PublicKeyCredential', class {})
        vi.stubGlobal('navigator', { credentials: { get } })
        vi.stubGlobal('AuthenticatorAssertionResponse', AssertionResponse)
        return { get, secret }
    }

    it('keeps PRF bytes local through the actual login HTTP serialization', async () => {
        const { secret } = setup()
        const fetch = vi.fn().mockResolvedValue(new Response('{}', { headers: { 'content-type': 'application/json' } }))
        vi.stubGlobal('fetch', fetch)
        const result = await webauthnLoginWithPrf({ challenge: 'AQID' })
        await v2LoginFinish({
            challengeId: 'dummy-challenge',
            credential: (result.raw as { credential: unknown }).credential,
        })
        const body = JSON.parse(fetch.mock.calls[0][1].body)
        expect(body.credential.clientExtensionResults).toEqual({ prf: { enabled: true } })
        expect(JSON.stringify(body)).not.toContain(Buffer.from(secret).toString('base64url'))
        expect(result.prfSecret).toEqual(secret)
    })

    it('requires UV even if the server supplied a weaker policy', async () => {
        const { get } = setup()
        await webauthnLoginWithPrf({ challenge: 'AQID', options: { publicKey: { userVerification: 'discouraged' } } })
        expect(get.mock.calls[0][0].publicKey.userVerification).toBe('required')
    })

    it('rejects an assertion without a verified user', async () => {
        setup(false)
        await expect(webauthnLoginWithPrf({ challenge: 'AQID' })).rejects.toThrow('User verification is required')
    })
})
