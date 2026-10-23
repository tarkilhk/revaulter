<script lang="ts">
import { onMount } from 'svelte'
import Button from '$components/Button.svelte'
import TextField from '$components/TextField.svelte'

let { onAnswer, keyProtection }: { keyProtection: 'prf' | 'bitwarden'; onAnswer: (password: string | null) => void } =
    $props()
let dialog: HTMLDialogElement
let password = $state('')

onMount(() => {
    dialog.showModal()
    return () => {
        password = ''
    }
})

function finish(value: string | null) {
    password = ''
    dialog.close()
    onAnswer(value)
}
</script>

<dialog bind:this={dialog} oncancel={(event) => { event.preventDefault(); finish(null) }} class="m-auto max-w-sm rounded-xl border border-neutral-300 bg-white p-6 text-neutral-950 shadow-xl backdrop:bg-black/40 dark:border-neutral-700 dark:bg-neutral-900 dark:text-white" aria-labelledby="fresh-password-title">
    <form onsubmit={(event) => { event.preventDefault(); finish(password) }}>
        <h2 id="fresh-password-title" class="mbe-2 text-lg font-semibold">Unlock this action</h2>
        <p class="mbe-4 text-sm text-neutral-600 dark:text-neutral-300">Your passkey was verified. Autofill its {keyProtection === 'bitwarden' ? 'Bitwarden unlock secret' : 'password'} to complete this action. Keys will be cleared when it finishes. {keyProtection === 'bitwarden' ? 'Use the Revaulter item password, never your Bitwarden master password or a CI token.' : ''}</p>
        <label for="fresh-password" class="mbe-1 block text-sm">{keyProtection === 'bitwarden' ? 'Unlock secret' : 'Passkey password'}</label>
        <TextField id="fresh-password" type="password" bind:value={password} autocomplete="current-password" autofocus />
        <div class="mbs-4 flex justify-end gap-2">
            <Button variant="ghost" onclick={() => finish(null)}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={!password}>Continue</Button>
        </div>
    </form>
</dialog>
