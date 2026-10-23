import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
    credentialPublicKeyHash,
    generatePrfSalt,
    serializePublicKeyCredential,
    serializeWebAuthnExtensionResults,
    webauthnLoginWithPrf,
    webauthnRegister,
} from '$lib/webauthn'

class FakeAuthenticatorAttestationResponse {
    attestationObject: ArrayBuffer
    clientDataJSON: ArrayBuffer

    constructor(attestationObject: ArrayBuffer, clientDataJSON: ArrayBuffer) {
        this.attestationObject = attestationObject
        this.clientDataJSON = clientDataJSON
    }
}

class FakeAuthenticatorAssertionResponse {
    authenticatorData: ArrayBuffer
    clientDataJSON: ArrayBuffer
    signature: ArrayBuffer
    userHandle: ArrayBuffer | null

    constructor(args: {
        authenticatorData: ArrayBuffer
        clientDataJSON: ArrayBuffer
        signature: ArrayBuffer
        userHandle?: ArrayBuffer | null
    }) {
        this.authenticatorData = args.authenticatorData
        this.clientDataJSON = args.clientDataJSON
        this.signature = args.signature
        this.userHandle = args.userHandle ?? null
    }
}

function bytes(...values: number[]): ArrayBuffer {
    return Uint8Array.from(values).buffer
}

// Minimal valid attestation object containing an ES256 COSE public key
const ATTESTATION_OBJECT_BASE64 =
    'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViHERERERERERERERERERERERERERERERERERERERERERFFAAAAAQAAAAAAAAAAAAAAAAAAAAAAAwECA6UBAgMmIAEhWCCqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqiJYILu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7'

function buildAttestationObject(): ArrayBuffer {
    const decoded = Buffer.from(ATTESTATION_OBJECT_BASE64, 'base64')
    return Uint8Array.from(decoded).buffer
}

// Cross-language fixtures for credential public keys that are not ECDSA
// Each is a fixed CBOR header, a body of repeated fill bytes standing in for the key material, and a fixed trailer
// These must stay identical to the fixtures in internal/protocolv2/credential_pubkey_test.go and cose-extract.test.ts
const COSE_FIXTURES = [
    {
        name: 'EdDSA',
        headerHex: 'a4010103272006215820',
        fill: 0xcc,
        bodyLen: 32,
        trailerHex: '',
        hash: 'cofjKg9veiFnYvNi8MMJxabBwzBlQPpJg1vXJH6fyt4',
    },
    {
        name: 'RS256',
        headerHex: 'a401030339010020590100',
        fill: 0xab,
        bodyLen: 256,
        trailerHex: '2143010001',
        hash: 'jaLEoC-xsM5H9AgJeo8GTDcJxd5nBh5R4qw8gUkBEdg',
    },
    {
        name: 'ML-DSA-44',
        headerHex: 'a3010703382f20590520',
        fill: 0xdd,
        bodyLen: 1312,
        trailerHex: '',
        hash: 'ag4GSXJUaUsb2zAkWkDsB_Uc9wNpi-zR90RqJnSJFDg',
    },
]

function buildFixtureCose(fixture: (typeof COSE_FIXTURES)[number]): Uint8Array {
    const header = Buffer.from(fixture.headerHex, 'hex')
    const trailer = Buffer.from(fixture.trailerHex, 'hex')
    const out = new Uint8Array(header.length + fixture.bodyLen + trailer.length)
    out.set(header, 0)
    out.fill(fixture.fill, header.length, header.length + fixture.bodyLen)
    out.set(trailer, header.length + fixture.bodyLen)
    return out
}

// Wraps a credential public key in the attestation object a PRF-capable authenticator produces
// The flags set AT and ED, so the key is followed by the authenticator extension outputs the extractor has to stop before
function buildFixtureAttestationObject(fixture: (typeof COSE_FIXTURES)[number]): ArrayBuffer {
    const credId = new TextEncoder().encode('cross-language-fixture-id')
    // {"hmac-secret": true}
    const extensions = Buffer.from('a16b686d61632d736563726574f5', 'hex')
    const authData = Buffer.concat([
        Buffer.alloc(32, 0x11),
        Buffer.from([0xc5, 0x00, 0x00, 0x00, 0x01]),
        Buffer.alloc(16),
        Buffer.from([(credId.length >> 8) & 0xff, credId.length & 0xff]),
        credId,
        buildFixtureCose(fixture),
        extensions,
    ])
    const attestationObject = Buffer.concat([
        // a3 | "fmt" -> "none" | "attStmt" -> {} | "authData" -> bstr(authData)
        Buffer.from('a363666d74646e6f6e656761747453746d74a068617574684461746159', 'hex'),
        Buffer.from([(authData.length >> 8) & 0xff, authData.length & 0xff]),
        authData,
    ])
    return Uint8Array.from(attestationObject).buffer
}

function verifiedAuthenticatorData(): ArrayBuffer {
    const data = new Uint8Array(37)
    data[32] = 0x05
    return data.buffer
}

function assertionCredential(
    extensionResults: unknown = { prf: { enabled: true, results: { first: bytes(9, 8, 7) } } }
) {
    return {
        id: 'assertion-id',
        rawId: bytes(1, 2, 3),
        type: 'public-key',
        response: new FakeAuthenticatorAssertionResponse({
            authenticatorData: verifiedAuthenticatorData(),
            clientDataJSON: bytes(6, 7),
            signature: bytes(8, 9),
            userHandle: bytes(10),
        }),
        getClientExtensionResults: () => extensionResults,
    } as unknown as PublicKeyCredential
}

beforeEach(() => {
    vi.stubGlobal('PublicKeyCredential', class PublicKeyCredential {})
    vi.stubGlobal('AuthenticatorAttestationResponse', FakeAuthenticatorAttestationResponse)
    vi.stubGlobal('AuthenticatorAssertionResponse', FakeAuthenticatorAssertionResponse)
})

afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
})

describe('generatePrfSalt', () => {
    it('fills a new 32-byte salt with the browser random source', () => {
        const getRandomValues = vi.spyOn(crypto, 'getRandomValues')
        const salt = generatePrfSalt()

        expect(salt).toHaveLength(32)
        expect(getRandomValues).toHaveBeenCalledOnce()
        expect(getRandomValues.mock.calls[0][0]).toBe(salt)
    })
})

describe('credentialPublicKeyHash', () => {
    it('hashes the exact COSE public key embedded in the attestation object', async () => {
        const response = new FakeAuthenticatorAttestationResponse(buildAttestationObject(), bytes())

        await expect(credentialPublicKeyHash(response as unknown as AuthenticatorAttestationResponse)).resolves.toBe(
            'YLaAiaKKf8P_gxCZdaWAwIiQLkrJAoCjl0QLZZb7sYk'
        )
    })

    // The hash is taken over the raw COSE bytes, so no key type needs its own handling here or on the server
    it.each(COSE_FIXTURES)(
        'hashes a $name credential public key to the digest the server computes',
        async (fixture) => {
            const response = new FakeAuthenticatorAttestationResponse(buildFixtureAttestationObject(fixture), bytes())

            await expect(
                credentialPublicKeyHash(response as unknown as AuthenticatorAttestationResponse)
            ).resolves.toBe(fixture.hash)
        }
    )
})

describe('serializePublicKeyCredential', () => {
    it('uses native core fields but normalizes the browser extension result', () => {
        const serialized = {
            id: 'credential',
            rawId: 'Y3JlZGVudGlhbA',
            type: 'public-key',
            clientExtensionResults: { prf: { results: { first: [251, 255, 0] } } },
        }
        const credential = {
            toJSON: () => serialized,
            getClientExtensionResults: () => ({
                prf: { results: { first: bytes(0xfb, 0xff, 0x00) } },
            }),
        } as unknown as PublicKeyCredential

        expect(serializePublicKeyCredential(credential)).toEqual({
            id: 'credential',
            rawId: 'Y3JlZGVudGlhbA',
            type: 'public-key',
            clientExtensionResults: {},
        })
    })

    it('manually serializes an attestation when the native serializer is unavailable', () => {
        const credential = {
            id: 'registration-id',
            rawId: bytes(1, 2, 3),
            type: 'public-key',
            response: new FakeAuthenticatorAttestationResponse(bytes(4, 5), bytes(6, 7)),
            getClientExtensionResults: () => ({}),
        } as unknown as PublicKeyCredential

        expect(serializePublicKeyCredential(credential)).toEqual({
            id: 'registration-id',
            rawId: 'AQID',
            type: 'public-key',
            clientExtensionResults: {},
            response: {
                attestationObject: 'BAU',
                clientDataJSON: 'Bgc',
            },
        })
    })

    it('manually serializes an assertion and its nullable user handle', () => {
        const credential = assertionCredential()

        expect(serializePublicKeyCredential(credential)).toEqual({
            id: 'assertion-id',
            rawId: 'AQID',
            type: 'public-key',
            clientExtensionResults: { prf: { enabled: true } },
            response: {
                authenticatorData: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF AAAAAA'.replace(' ', ''),
                clientDataJSON: 'Bgc',
                signature: 'CAk',
                userHandle: 'Cg',
            },
        })

        ;(credential.response as FakeAuthenticatorAssertionResponse).userHandle = null
        expect(
            (serializePublicKeyCredential(credential) as { response: { userHandle?: string } }).response.userHandle
        ).toBeUndefined()
    })

    it.each([null, 'invalid'])('falls back when toJSON returns %j', (nativeResult) => {
        const credential = {
            id: 'credential',
            rawId: bytes(1),
            type: 'public-key',
            response: {},
            toJSON: () => nativeResult,
        } as unknown as PublicKeyCredential

        expect(serializePublicKeyCredential(credential)).toEqual({
            id: 'credential',
            rawId: 'AQ',
            type: 'public-key',
            clientExtensionResults: undefined,
        })
    })
})

describe('serializeWebAuthnExtensionResults', () => {
    it.each([
        { prf: { results: { first: bytes(1, 2), second: [3, 4] } } },
        { prf: { results: { first: 'secret' } }, future: { secret: bytes(1) } },
        { 'hmac-secret': bytes(9), largeBlob: { blob: bytes(8) } },
    ])('drops secret and unknown extension data', (input) => {
        expect(serializeWebAuthnExtensionResults(input)).toEqual({})
    })

    it('keeps only the public PRF capability', () => {
        expect(serializeWebAuthnExtensionResults({ prf: { enabled: true, results: { first: bytes(1) } } })).toEqual({
            prf: { enabled: true },
        })
    })
})

describe('webauthnRegister', () => {
    it('rejects unavailable WebAuthn and malformed server options', async () => {
        vi.stubGlobal('navigator', {})
        await expect(webauthnRegister({ options: {} })).rejects.toThrow('WebAuthn is not available in this browser')

        vi.stubGlobal('navigator', { credentials: {} })
        await expect(webauthnRegister({ options: {} })).rejects.toThrow(
            'WebAuthn registration requires server-provided creation options'
        )
    })

    it('decodes binary options while preserving relying-party strings', async () => {
        const create = vi.fn().mockResolvedValue(null)
        vi.stubGlobal('navigator', { credentials: { create } })

        await expect(
            webauthnRegister({
                options: {
                    publicKey: {
                        challenge: 'AQID',
                        rp: { id: 'example.com', name: 'Example' },
                        user: { id: 'BAU', name: 'user', displayName: 'User' },
                        excludeCredentials: [{ type: 'public-key', id: 'Bgc' }],
                        pubKeyCredParams: [],
                    },
                },
            })
        ).rejects.toThrow('WebAuthn registration was canceled')

        const options = create.mock.calls[0][0].publicKey
        expect(Array.from(options.challenge)).toEqual([1, 2, 3])
        expect(Array.from(options.user.id)).toEqual([4, 5])
        expect(Array.from(options.excludeCredentials[0].id)).toEqual([6, 7])
        expect(options.rp.id).toBe('example.com')
    })

    it('returns the serialized credential and public-key hash', async () => {
        const response = new FakeAuthenticatorAttestationResponse(buildAttestationObject(), bytes(6, 7))
        const credential = {
            id: 'registration-id',
            rawId: bytes(1, 2, 3),
            type: 'public-key',
            response,
            getClientExtensionResults: () => ({ prf: { enabled: true } }),
        } as unknown as PublicKeyCredential
        vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(credential) } })

        const result = await webauthnRegister({ options: { publicKey: { challenge: 'AQID' } } })

        expect(result.id).toBe('registration-id')
        expect(result.signCount).toBe(0)
        expect(result.publicKeyHash).toBe('YLaAiaKKf8P_gxCZdaWAwIiQLkrJAoCjl0QLZZb7sYk')
        expect(result.raw).toMatchObject({
            credential: { id: 'registration-id', rawId: 'AQID' },
            clientDataJSON: 'Bgc',
        })
    })

    it.each([{}, { prf: {} }, { prf: { enabled: false } }])(
        'rejects a newly-created credential without confirmed PRF support before serialization',
        async (extensionResults) => {
            const credential = {
                id: 'registration-id',
                rawId: bytes(1, 2, 3),
                type: 'public-key',
                response: new FakeAuthenticatorAttestationResponse(buildAttestationObject(), bytes(6, 7)),
                getClientExtensionResults: () => extensionResults,
            } as unknown as PublicKeyCredential
            vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(credential) } })

            await expect(webauthnRegister({ options: { publicKey: { challenge: 'AQID' } } })).rejects.toThrow(
                'PRF is unavailable for this credential'
            )
        }
    )

    it.each(COSE_FIXTURES)('returns the public-key hash for a $name credential', async (fixture) => {
        const response = new FakeAuthenticatorAttestationResponse(buildFixtureAttestationObject(fixture), bytes(6, 7))
        const credential = {
            id: 'registration-id',
            rawId: bytes(1, 2, 3),
            type: 'public-key',
            response,
            getClientExtensionResults: () => ({ prf: { enabled: true } }),
        } as unknown as PublicKeyCredential
        vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(credential) } })

        const result = await webauthnRegister({ options: { publicKey: { challenge: 'AQID' } } })

        expect(result.publicKeyHash).toBe(fixture.hash)
    })
})

describe('webauthnLoginWithPrf', () => {
    it('rejects unavailable WebAuthn', async () => {
        vi.stubGlobal('navigator', {})
        await expect(webauthnLoginWithPrf({ challenge: 'AQID' })).rejects.toThrow(
            'WebAuthn is not available in this browser'
        )
    })

    it('decodes server options and overrides attempt-specific challenge and PRF input', async () => {
        const get = vi.fn().mockResolvedValue(null)
        vi.stubGlobal('navigator', { credentials: { get } })
        const salt = Uint8Array.from([9, 8, 7])

        await expect(
            webauthnLoginWithPrf({
                challenge: 'AQID',
                prfSalt: salt,
                options: {
                    publicKey: {
                        challenge: 'AAAA',
                        rpId: 'example.com',
                        allowCredentials: [{ type: 'public-key', id: 'BAU' }],
                        extensions: { appid: 'https://example.com' },
                    },
                },
            })
        ).rejects.toThrow('WebAuthn authentication was canceled')

        const options = get.mock.calls[0][0].publicKey
        expect(Array.from(options.challenge)).toEqual([1, 2, 3])
        expect(Array.from(options.allowCredentials[0].id)).toEqual([4, 5])
        expect(options.rpId).toBe('example.com')
        expect(options.extensions.appid).toBe('https://example.com')
        expect(Array.from(new Uint8Array(options.extensions.prf.eval.first))).toEqual([9, 8, 7])
    })

    it('uses fallback request policy when the server options are absent', async () => {
        const get = vi.fn().mockResolvedValue(null)
        vi.stubGlobal('navigator', { credentials: { get } })

        await expect(webauthnLoginWithPrf({ challenge: 'AQID', prfSalt: Uint8Array.from([1]) })).rejects.toThrow(
            'WebAuthn authentication was canceled'
        )

        expect(get.mock.calls[0][0].publicKey).toMatchObject({
            timeout: 60_000,
            userVerification: 'required',
        })
    })

    it('rejects an assertion without PRF output', async () => {
        vi.stubGlobal('navigator', {
            credentials: { get: vi.fn().mockResolvedValue(assertionCredential({ prf: { enabled: false } })) },
        })

        await expect(webauthnLoginWithPrf({ challenge: 'AQID' })).rejects.toThrow(
            'Authenticator did not return PRF output'
        )
    })

    it('returns the PRF secret and serialized assertion', async () => {
        vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(assertionCredential()) } })

        const result = await webauthnLoginWithPrf({ challenge: 'AQID', prfSalt: Uint8Array.from([1, 2]) })

        expect(result.id).toBe('assertion-id')
        expect(Array.from(result.prfSecret ?? [])).toEqual([9, 8, 7])
        expect(result.raw).toMatchObject({
            credential: {
                id: 'assertion-id',
                clientExtensionResults: { prf: { enabled: true } },
                response: {
                    authenticatorData: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF AAAAAA'.replace(' ', ''),
                    clientDataJSON: 'Bgc',
                    signature: 'CAk',
                    userHandle: 'Cg',
                },
            },
            authenticatorData: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF AAAAAA'.replace(' ', ''),
            clientDataJSON: 'Bgc',
            signature: 'CAk',
            userHandle: 'Cg',
            prfEnabled: true,
        })
    })
})
