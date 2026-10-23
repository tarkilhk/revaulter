package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

func validKeyProtection(mode string) bool {
	return mode == "prf" || mode == "bitwarden"
}

func requireCredentialProtection(cred *webauthnlib.Credential, mode string) error {
	// Existing registration challenges belong to the PRF flow
	if mode == "" || mode == "prf" {
		return requirePRFSupport(cred)
	}
	if mode != "bitwarden" || cred == nil {
		return NewResponseError(http.StatusBadRequest, "Unsupported key protection")
	}
	return nil
}

// Enforce the immutable credential mode before accepting ciphertext
// Cryptographic authentication of these fields is performed by the browser AEAD
func validateProtectionEnvelope(wrapped, mode, credentialID string) error {
	var envelope struct {
		V                int    `json:"v"`
		Mode             string `json:"mode"`
		CredentialHash   string `json:"credentialHash"`
		PasswordRequired bool   `json:"passwordRequired"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "Invalid wrapped key")
	}
	err = json.Unmarshal(raw, &envelope)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "Invalid wrapped key")
	}
	if mode == "prf" && envelope.V == 1 && envelope.Mode == "" && envelope.CredentialHash == "" {
		return nil
	}
	if mode == "bitwarden" && envelope.V == 2 && envelope.Mode == mode && envelope.CredentialHash == protectionCredentialHash(credentialID) && envelope.PasswordRequired {
		return nil
	}
	return NewResponseError(http.StatusBadRequest, "Wrapped key does not match credential protection")
}

func protectionCredentialHash(credentialID string) string {
	digest := sha256.Sum256([]byte(credentialID))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
