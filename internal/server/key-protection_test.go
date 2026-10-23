package server

import (
	"encoding/base64"
	"testing"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

func TestExplicitKeyProtection(t *testing.T) {
	credential := &webauthnlib.Credential{}
	err := requireCredentialProtection(credential, "bitwarden")
	require.NoError(t, err)
	err = requireCredentialProtection(credential, "prf")
	require.Error(t, err)
	err = requireCredentialProtection(credential, "unexpected")
	require.Error(t, err)

	prf := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"passwordRequired":false,"nonce":"dummy","ciphertext":"dummy"}`))
	bitwarden := base64.RawURLEncoding.EncodeToString([]byte(`{"v":2,"mode":"bitwarden","credentialHash":"` + protectionCredentialHash("credential") + `","passwordRequired":true,"nonce":"dummy","ciphertext":"dummy"}`))
	for _, test := range []struct {
		name, envelope, mode, credential string
		valid                            bool
	}{
		{"existing PRF", prf, "prf", "credential", true},
		{"explicit Bitwarden", bitwarden, "bitwarden", "credential", true},
		{"PRF cannot downgrade", bitwarden, "prf", "credential", false},
		{"Bitwarden cannot masquerade as PRF", prf, "bitwarden", "credential", false},
		{"credential mismatch", bitwarden, "bitwarden", "different", false},
		{"mode unsupported", bitwarden, "unknown", "credential", false},
		{"empty wrapper", "", "bitwarden", "credential", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateProtectionEnvelope(test.envelope, test.mode, test.credential)
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
