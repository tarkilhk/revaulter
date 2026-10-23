<script lang="ts">
import heroImage from '$assets/hero.avif'
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import Logo from '$components/Logo.svelte'
import TextField from '$components/TextField.svelte'

interface Props {
    keyProtection: 'prf' | 'bitwarden'
    onKeyProtectionInput: (value: 'prf' | 'bitwarden') => void
    authBusy: boolean
    authError: string | null
    authErrorHelpHref: string | null
    displayName: string
    onDisplayNameInput: (value: string) => void
    onPasswordInput: (value: string) => void
    onRegister: () => Promise<void>
    onReturnToSignIn: () => Promise<void>
    onSetPassword: () => Promise<void>
    onSkipPassword: () => void
    pageError: string | null
    passwordInput: string
    uiState: 'signup' | 'password-setup'
}

let {
    keyProtection,
    onKeyProtectionInput,
    authBusy,
    authError,
    authErrorHelpHref,
    displayName,
    onDisplayNameInput,
    onPasswordInput,
    onRegister,
    onReturnToSignIn,
    onSetPassword,
    onSkipPassword,
    pageError,
    passwordInput,
    uiState,
}: Props = $props()

let passwordConfirm = $state('')
let confirmError = $state<string | null>(null)
let secretSaved = $state(false)

function handleSetPassword() {
    confirmError = null
    if (keyProtection === 'bitwarden' && !secretSaved) {
        confirmError = 'Save the unlock secret in Bitwarden before continuing'
        return
    }
    if (keyProtection === 'prf' && passwordInput !== passwordConfirm) {
        confirmError = 'Passwords do not match'
        return
    }
    passwordConfirm = ''
    secretSaved = false
    void onSetPassword()
}

function authHeadline() {
    if (uiState === 'signup') {
        return 'Create a new account'
    }
    return keyProtection === 'bitwarden' ? 'Save your unlock secret' : 'Add a password'
}

function authBodyCopy() {
    if (uiState === 'signup') {
        return 'Choose how to protect your local keys, then register a passkey. This choice will not change automatically.'
    }
    if (keyProtection === 'bitwarden') {
        return 'Save this generated secret as the password in the same Bitwarden login item as your Revaulter passkey. Autofill it for each approval. This is not your Bitwarden master password or a CI token. Losing it loses access to these keys.'
    }
    return 'Passwords are optional. If you set one now, Revaulter will ask for it after future passkey sign-ins before unlocking local keys.'
}
</script>

<div class="grid min-h-screen grid-cols-1 lg:grid-cols-2">
    <!-- Left pane: form -->
    <div class="flex min-h-screen items-center justify-center px-6 py-12">
        <div class="w-full max-w-90">
            <div class="mb-8">
                <Logo size={48} />
            </div>

            <h1 class="mb-2 text-[30px] font-semibold leading-tight tracking-tight text-neutral-950 dark:text-neutral-50">
                {authHeadline()}
            </h1>
            <p class="mb-8 text-[15px] leading-6 text-neutral-500 dark:text-neutral-400">
                {authBodyCopy()}
            </p>

            {#if pageError}
                <div class="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {pageError}
                </div>
            {/if}

            {#if authError}
                <div class="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {authError}
                    {#if authErrorHelpHref}
                        <a class="ml-1 underline" href={authErrorHelpHref} target="_blank" rel="noreferrer">Learn about compatible passkeys.</a>
                    {/if}
                </div>
            {/if}

            {#if uiState === 'signup'}
                <form
                    class="space-y-4"
                    onsubmit={(event) => {
                        event.preventDefault()
                        if (!authBusy) {
                            void onRegister()
                        }
                    }}
                >
                    <fieldset class="space-y-2" disabled={authBusy}>
                        <legend class="text-sm font-medium">Key protection</legend>
                        <label class="block text-sm"><input type="radio" name="key-protection" checked={keyProtection === 'prf'} onchange={() => onKeyProtectionInput('prf')} /> PRF passkey</label>
                        <label class="block text-sm"><input type="radio" name="key-protection" checked={keyProtection === 'bitwarden'} onchange={() => onKeyProtectionInput('bitwarden')} /> Bitwarden passkey and unlock secret</label>
                        <p class="text-sm text-neutral-500">Bitwarden mode uses an ordinary passkey plus a separate generated secret for browser-only decryption. A fresh passkey verification does not always prompt for a fingerprint.</p>
                    </fieldset>
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-neutral-900 dark:text-neutral-100" for="v2-displayname">Display name (optional)</label>
                        <TextField
                            id="v2-displayname"
                            value={displayName}
                            oninput={(event) => {
                                onDisplayNameInput((event.currentTarget as HTMLInputElement).value)
                            }}
                        />
                    </div>

                    <Button
                        type="submit"
                        variant="primary"
                        size="lg"
                        width="full"
                        disabled={authBusy}
                    >
                        {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                        <Icon icon="key" title="Passkey" size="4" />
                        Create account with passkey
                    </Button>
                </form>
            {:else}
                <form
                    class="space-y-4"
                    onsubmit={(event) => {
                        event.preventDefault()
                        if (!authBusy) {
                            handleSetPassword()
                        }
                    }}
                >
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-neutral-900 dark:text-neutral-100" for="v2-password-setup">{keyProtection === 'bitwarden' ? 'Unlock secret' : 'Password'}</label>
                        <TextField
                            id="v2-password-setup"
                            type={keyProtection === 'bitwarden' ? 'text' : 'password'}
                            autocomplete="new-password"
                            value={passwordInput}
                            oninput={(event) => {
                                confirmError = null
                                onPasswordInput((event.currentTarget as HTMLInputElement).value)
                            }}
                        />
                    </div>

                    {#if keyProtection === 'bitwarden'}
                        <label class="block text-sm"><input type="checkbox" bind:checked={secretSaved} /> I saved this secret in my Revaulter Bitwarden login item.</label>
                        <p class="text-sm text-neutral-500">Use an item-specific URI rule restricted to this HTTPS origin. Keep other sites out of this item.</p>
                    {:else}
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-neutral-900 dark:text-neutral-100" for="v2-password-confirm">Confirm password</label>
                        <TextField
                            id="v2-password-confirm"
                            type="password"
                            bind:value={passwordConfirm}
                            oninput={() => {
                                confirmError = null
                            }}
                        />
                    </div>

                    {/if}
                    {#if confirmError}
                        <div class="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                            {confirmError}
                        </div>
                    {/if}

                    <div class="flex flex-col gap-3 sm:flex-row">
                        <Button
                            type="submit"
                            class="flex-1"
                            variant="primary"
                            size="lg"
                            disabled={authBusy}
                        >
                            {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                            {keyProtection === 'bitwarden' ? 'Finish setup' : 'Save password'}
                        </Button>
                        {#if keyProtection === 'prf'}
                        <Button
                            type="button"
                            class="flex-1"
                            variant="secondary"
                            size="lg"
                            onclick={async (event) => {
                                event.preventDefault()
                                onSkipPassword()
                            }}
                            disabled={authBusy}
                        >
                            Skip password
                        </Button>
                        {/if}
                    </div>
                </form>
            {/if}

            <div class="mt-8 border-t border-neutral-200 pt-6 dark:border-neutral-800">
                <button
                    type="button"
                    class="cursor-pointer text-sm text-neutral-500 underline decoration-neutral-300 underline-offset-4 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:decoration-neutral-700 dark:hover:text-neutral-50"
                    onclick={() => {
                        void onReturnToSignIn()
                    }}
                >
                    Back to sign in
                </button>
            </div>
        </div>
    </div>

    <!-- Right pane: hero image -->
    <div class="hidden p-4 lg:block">
        <div
            class="relative h-[calc(100vh-2rem)] w-full overflow-hidden rounded-[20px] border border-neutral-200 bg-cover bg-center dark:border-neutral-800"
            style={`background-image: url(${heroImage});`}
        >
            <div class="pointer-events-none absolute inset-0 rounded-[20px] ring-1 ring-inset ring-black/5"></div>
        </div>
    </div>
</div>
