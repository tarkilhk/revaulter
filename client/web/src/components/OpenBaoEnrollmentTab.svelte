<script lang="ts">
import { onMount } from 'svelte'
import Button from '$components/Button.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import { type EnrollOpenBao, type OpenBaoEnrollmentStatus, prepareOpenBaoBundle } from '$lib/openbao-enrollment'
import { ThrowResponseNotOk } from '$lib/request'

let { onEnroll }: { onEnroll: EnrollOpenBao } = $props()
let status = $state<OpenBaoEnrollmentStatus | null>(null)
let stage = $state<'loading' | 'ready' | 'verifying' | 'encrypting' | 'saving' | 'success' | 'error'>('loading')
let error = $state('')
let firstInput = $state<HTMLInputElement>()
let secondInput = $state<HTMLInputElement>()
let controller = new AbortController()
let plaintext: Uint8Array | undefined
let departed = false
const busy = $derived(stage === 'verifying' || stage === 'encrypting' || stage === 'saving')

function clearInputs() {
    if (firstInput) {
        firstInput.value = ''
    }
    if (secondInput) {
        secondInput.value = ''
    }
}

function clearOperation() {
    controller.abort()
    plaintext?.fill(0)
    plaintext = undefined
    clearInputs()
}

function leave() {
    departed = true
    clearOperation()
}

async function load() {
    stage = 'loading'
    error = ''
    controller = new AbortController()
    try {
        const response = await fetch('/v2/auth/openbao-enrollment', {
            credentials: 'same-origin',
            cache: 'no-store',
            signal: controller.signal,
        })
        await ThrowResponseNotOk(response)
        const result = (await response.json()) as OpenBaoEnrollmentStatus
        if (!departed) {
            status = result
            stage = 'ready'
        }
    } catch {
        if (!departed) {
            error = 'Could not load OpenBao enrollment. Check your connection and try again.'
            stage = 'error'
        }
    }
}

async function enroll(event: SubmitEvent) {
    event.preventDefault()
    if (busy || !status?.enabled || !status.requestKeyEnabled) {
        return
    }
    error = ''
    try {
        plaintext = prepareOpenBaoBundle(status.target, firstInput?.value ?? '', secondInput?.value ?? '')
    } catch (err) {
        clearInputs()
        error = err instanceof Error ? err.message : 'Check both shares and try again.'
        return
    }
    clearInputs()
    controller = new AbortController()
    const signal = controller.signal
    stage = 'verifying'
    try {
        await onEnroll(plaintext, signal, (next) => {
            if (!departed && !signal.aborted) {
                stage = next
            }
        })
        if (!departed && !signal.aborted) {
            status = { ...status, enrolled: true }
            stage = 'success'
        }
    } catch {
        if (!departed && !signal.aborted) {
            error =
                'Enrollment was not confirmed. Reload the status before trying again. Your entered shares have been cleared.'
            status = null
            stage = 'error'
        }
    } finally {
        plaintext?.fill(0)
        plaintext = undefined
        clearInputs()
    }
}

onMount(() => {
    void load()
    const restore = (event: PageTransitionEvent) => {
        if (event.persisted) {
            departed = false
            void load()
        }
    }
    window.addEventListener('pagehide', leave)
    window.addEventListener('pageshow', restore)
    return () => {
        leave()
        window.removeEventListener('pagehide', leave)
        window.removeEventListener('pageshow', restore)
    }
})
</script>

<div class="max-w-xl space-y-5">
    <div class="space-y-2">
        <h2 class="text-sm font-medium text-neutral-900 dark:text-neutral-50">OpenBao unseal enrollment</h2>
        <p class="text-sm text-neutral-500 dark:text-neutral-400">Encrypt two unseal shares for approval from your phone. Only the encrypted bundle is uploaded and saved on the server.</p>
    </div>

    {#if stage === 'loading'}
        <div role="status" class="flex items-center gap-2 text-sm"><LoadingSpinner /> Loading enrollment…</div>
    {:else if status && !status.enabled}
        <p class="text-sm">Enrollment is unavailable for this account. Ask the operator to check the server configuration.</p>
    {:else if status && !status.requestKeyEnabled}
        <p class="text-sm">Enable Request key in Settings → Request auth to let OpenBao send approval requests to this account.</p>
    {:else if status}
        <div class="space-y-1 text-sm">
            <p class="font-medium">{status.enrolled ? 'Encrypted shares saved' : 'No shares enrolled'}</p>
            <p class="break-all text-neutral-500 dark:text-neutral-400">Target: {status.target}</p>
            {#if status.enrolled}
                <p>Saving replaces the shared enrollment. Future unlock requests go to your account.</p>
            {/if}
        </div>
        {#if stage === 'success'}
            <p role="status" class="text-sm">Enrollment saved. Your entered shares have been cleared. Future unseal requests require your approval.</p>
        {/if}
        <form onsubmit={enroll} autocomplete="off" class="space-y-4">
            {#each [1, 2] as index}
                <div class="space-y-1.5">
                    <label class="block text-sm font-medium" for={`openbao-share-${index}`}>Unseal share {index}</label>
                    {#if index === 1}
                        <input bind:this={firstInput} id="openbao-share-1" type="password" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore autocapitalize="off" autocorrect="off" spellcheck="false" required disabled={busy} class="w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-base focus-visible:outline-2 focus-visible:outline-offset-2 dark:border-neutral-700 dark:bg-neutral-950" />
                    {:else}
                        <input bind:this={secondInput} id="openbao-share-2" type="password" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore autocapitalize="off" autocorrect="off" spellcheck="false" required disabled={busy} class="w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-base focus-visible:outline-2 focus-visible:outline-offset-2 dark:border-neutral-700 dark:bg-neutral-950" />
                    {/if}
                </div>
            {/each}
            <p class="text-xs text-neutral-500 dark:text-neutral-400">Enter two different base64 shares. This page does not save plaintext shares in browser storage. Keep the original shares in your secure backup. Browser memory and clipboard history cannot be guaranteed erased.</p>
            {#if busy}
                <div role="status" class="flex items-center gap-2 text-sm"><LoadingSpinner /> {stage === 'verifying' ? 'Verify with your passkey to continue…' : stage === 'encrypting' ? 'Encrypting shares in this browser…' : 'Saving encrypted enrollment…'}</div>
            {/if}
            <div class="flex flex-wrap gap-2">
                <Button type="submit" variant="primary" disabled={busy}>{status.enrolled ? 'Replace encrypted shares' : 'Encrypt and enroll'}</Button>
                <Button disabled={busy} onclick={clearInputs}>Clear shares</Button>
            </div>
        </form>
    {/if}
    {#if error}
        <p role="alert" class="text-sm text-rose-700 dark:text-rose-300">{error}</p>
        {#if !status}<Button onclick={load}>Reload status</Button>{/if}
    {/if}
</div>
