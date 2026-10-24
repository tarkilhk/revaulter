import { describe, expect, it } from 'vitest'
import { deriveOperationKeyBytes } from '$lib/crypto'
import { performAesGcmOperation } from '$lib/crypto-symmetric'
import { encryptOpenBaoBundle, prepareOpenBaoBundle } from '$lib/openbao-enrollment'
import { base64UrlToBytes } from '$lib/utils'

const first = btoa(String.fromCharCode(...new Uint8Array(33).fill(1)))
const second = btoa(String.fromCharCode(...new Uint8Array(33).fill(2)))
const target = 'https://bao.example.test'

describe('OpenBao browser enrollment', () => {
    it('encrypts the worker bundle with the existing operation key and clears plaintext', async () => {
        const plaintext = prepareOpenBaoBundle(target, first, second)
        const primaryKey = new Uint8Array(32).fill(7)
        const envelope = await encryptOpenBaoBundle(plaintext, primaryKey, 'dummy-owner', new AbortController().signal)
        expect(plaintext.every((byte) => byte === 0)).toBe(true)
        expect(JSON.stringify(envelope)).not.toContain(first)
        expect(JSON.stringify(envelope)).not.toContain(second)
        const keyBytes = await deriveOperationKeyBytes({
            primaryKey,
            userId: 'dummy-owner',
            keyLabel: envelope.keyLabel,
            algorithm: envelope.algorithm,
        })
        const decrypted = await performAesGcmOperation({
            mode: 'decrypt',
            keyBytes,
            value: base64UrlToBytes(envelope.value),
            nonce: base64UrlToBytes(envelope.nonce),
            tag: base64UrlToBytes(envelope.tag),
        })
        expect(JSON.parse(new TextDecoder().decode(decrypted))).toEqual({ version: 1, target, shares: [first, second] })
        decrypted.fill(0)
        keyBytes.fill(0)
        primaryKey.fill(0)
    })

    it('rejects duplicate or malformed shares and non-origin targets', () => {
        expect(() => prepareOpenBaoBundle(target, first, first)).toThrow('different')
        expect(() => prepareOpenBaoBundle(target, first, 'invalid')).toThrow('33 bytes')
        expect(() => prepareOpenBaoBundle('http://bao.example.test', first, second)).toThrow('target')
        expect(() => prepareOpenBaoBundle(`${target}/path`, first, second)).toThrow('target')
    })

    it('clears plaintext when canceled before deriving a key', async () => {
        const plaintext = prepareOpenBaoBundle(target, first, second)
        const controller = new AbortController()
        controller.abort()
        await expect(encryptOpenBaoBundle(plaintext, new Uint8Array(32), 'dummy', controller.signal)).rejects.toThrow()
        expect(plaintext.every((byte) => byte === 0)).toBe(true)
    })
})
