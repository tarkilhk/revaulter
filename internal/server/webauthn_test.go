package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

func TestInitWebAuthnAddsRelatedOriginRequestsFromConfiguredOrigins(t *testing.T) {
	t.Cleanup(
		config.SetTestConfig(map[string]any{
			"baseUrl":        "https://auth.example.com",
			"webauthnRpId":   "example.com",
			"webauthnRpName": "Revaulter",
			"webauthnOrigins": []string{
				"https://auth.example.com",
				"https://console.example.com",
				"https://console.example.com/",
				"https://admin.example.com",
			},
		}),
	)

	wa, err := (&Server{}).initWebAuthn()
	require.NoError(t, err)
	require.NotNil(t, wa)
	assert.Equal(t, protocol.VerificationRequired, wa.Config.AuthenticatorSelection.UserVerification)

	require.Equal(t, []string{
		"https://auth.example.com",
		"https://console.example.com",
		"https://admin.example.com",
	}, wa.Config.RPOrigins)
	assert.Equal(t, []string{
		"https://auth.example.com",
		"https://console.example.com",
		"https://admin.example.com",
	}, wa.Config.RPTopOrigins)
	assert.Equal(t, protocol.TopOriginExplicitVerificationMode, wa.Config.RPTopOriginVerificationMode)
}

func TestInitWebAuthnIgnoresWildcardOriginsForRelatedOriginRequests(t *testing.T) {
	t.Cleanup(
		config.SetTestConfig(map[string]any{
			"baseUrl":        "https://auth.example.com",
			"webauthnRpId":   "example.com",
			"webauthnRpName": "Revaulter",
			"webauthnOrigins": []string{
				"*",
			},
		}),
	)

	wa, err := (&Server{}).initWebAuthn()
	require.NoError(t, err)
	require.NotNil(t, wa)
	assert.Equal(t, protocol.VerificationRequired, wa.Config.AuthenticatorSelection.UserVerification)

	assert.Equal(t, []string{"https://auth.example.com"}, wa.Config.RPOrigins)
	assert.Empty(t, wa.Config.RPTopOrigins)
	assert.Equal(t, protocol.TopOriginExplicitVerificationMode, wa.Config.RPTopOriginVerificationMode)
}

func TestLogWebAuthnErrorIncludesConciseStructuredDiagnostic(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	ctx := logging.LogToContext(t.Context(), logger)
	protocolErr := protocol.ErrBadRequest.
		WithDetails("Parse error for Assertion").
		WithInfo("sensitive debug details")

	logWebAuthnError(ctx, "login", protocolErr)

	logOutput := output.String()
	assert.Contains(t, logOutput, "WebAuthn ceremony failed")
	assert.Contains(t, logOutput, "ceremony=login")
	assert.Contains(t, logOutput, "webauthn_error_type=invalid_request")
	assert.Contains(t, logOutput, `webauthn_error_details="Parse error for Assertion"`)
	assert.NotContains(t, logOutput, "webauthn_debug=")
	assert.NotContains(t, logOutput, "webauthn_cause=")
	assert.NotContains(t, logOutput, "webauthn_field_types=")
	assert.NotContains(t, logOutput, "sensitive debug details")
}

func TestRejectWebAuthnSecrets(t *testing.T) {
	for _, raw := range []string{
		`{"clientExtensionResults":{"prf":{"results":{"first":"dummy-secret"}}}}`,
		`{"clientExtensionResults":{"prf":{"results":{"first":[1,2,3]}}}}`,
		`{"clientExtensionResults":{"prf":{"results":null}}}`,
		`{"clientExtensionResults":{"hmac-secret":"dummy-secret"}}`,
	} {
		_, err := rejectWebAuthnSecrets(json.RawMessage(raw))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "dummy-secret")
	}
	raw := json.RawMessage(`{"id":"credential","clientExtensionResults":{"prf":{"enabled":true}}}`)
	got, err := rejectWebAuthnSecrets(raw)
	require.NoError(t, err)
	assert.JSONEq(t, string(raw), string(got))
}

func TestCredentialCreationWithoutExclusionsRemovesBrowserExclusionList(t *testing.T) {
	creation := &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: protocol.URLEncodedBase64("challenge"),
			CredentialExcludeList: []protocol.CredentialDescriptor{
				{
					Type:         protocol.PublicKeyCredentialType,
					CredentialID: protocol.URLEncodedBase64("existing-credential"),
				},
			},
		},
	}

	res, ok := credentialCreationWithoutExclusions(creation).(*protocol.CredentialCreation)
	require.True(t, ok)
	require.NotSame(t, creation, res)
	assert.Empty(t, res.Response.CredentialExcludeList)
	assert.Len(t, creation.Response.CredentialExcludeList, 1)
}
