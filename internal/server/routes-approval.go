package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/italypaleale/revaulter/internal/db"
)

const approvalTTL = 2 * time.Minute

type approvalBinding struct {
	CredentialID       string `json:"credentialId"`
	CredentialRecordID string `json:"credentialRecordId"`
	PublicKeyDigest    string `json:"publicKeyDigest"`
	KeyProtection      string `json:"keyProtection"`
	UserEpoch          int64  `json:"userEpoch"`
	CredentialEpoch    int64  `json:"credentialEpoch"`
	State              string `json:"state"`
	Action             string `json:"action"`
	RequestDigest      string `json:"requestDigest"`
}

type approvalChallenge struct {
	Binding approvalBinding          `json:"binding"`
	Session *webauthnlib.SessionData `json:"session"`
}

func approvalDenied() error {
	return NewResponseError(http.StatusForbidden, "Fresh approval is invalid or expired")
}

func approvalDigest(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validApprovalPurpose(state, action string) bool {
	if state != "" {
		return action == ""
	}
	return action == "" || action == "add-credential" || action == "update-wrapped-key"
}

func (s *Server) approvalIdentity(ctx context.Context, tx *db.DbTx, userID, credentialID, state, action string) (approvalBinding, error) {
	var binding approvalBinding
	if userID == "" || credentialID == "" || !validApprovalPurpose(state, action) {
		return binding, approvalDenied()
	}
	as := tx.AuthStore()
	err := as.LockApprovalIdentity(ctx, userID, credentialID)
	if err != nil {
		return binding, approvalDenied()
	}
	user, err := as.GetUserByID(ctx, userID)
	if err != nil {
		return binding, err
	}
	if user == nil || user.Status != "active" || !user.Ready {
		return binding, approvalDenied()
	}
	credential, err := as.GetCredentialForUser(ctx, userID, credentialID)
	if err != nil {
		return binding, err
	}
	if credential == nil || (credential.KeyProtection != "prf" && credential.KeyProtection != "bitwarden") {
		return binding, approvalDenied()
	}
	binding = approvalBinding{CredentialID: credentialID, CredentialRecordID: credential.ID, PublicKeyDigest: approvalDigest(credential.PublicKey), KeyProtection: credential.KeyProtection, UserEpoch: user.WrappedKeyEpoch, CredentialEpoch: credential.WrappedKeyEpoch, State: state, Action: action}
	if state != "" {
		record, readErr := tx.RequestStore().GetRequest(ctx, state)
		if readErr != nil {
			return binding, readErr
		}
		if record == nil || record.UserID != userID || record.Status != db.V2RequestStatusPending || !record.ExpiresAt.After(time.Now()) {
			return binding, approvalDenied()
		}
		// The complete immutable record includes the encrypted client transport keys and ciphertext
		binding.RequestDigest = approvalDigest(struct {
			State, Owner, Operation, KeyLabel, Algorithm, EncryptedRequest, Note, Requestor string
			Created, Expires                                                                time.Time
		}{record.State, record.UserID, record.Operation, record.KeyLabel, record.Algorithm, record.EncryptedRequest, record.Note, record.RequestorIP, record.CreatedAt, record.ExpiresAt})
	}
	return binding, nil
}

func (s *Server) RouteV2AuthApprovalBegin(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}
	var req struct {
		CredentialID string `json:"credentialId"`
		State        string `json:"state"`
		Action       string `json:"action"`
	}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, approvalDenied())
		return
	}
	var cleanup *db.AuthChallenge
	result, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (any, error) {
		binding, err := s.approvalIdentity(ctx, tx, userID, req.CredentialID, req.State, req.Action)
		if err != nil {
			return nil, err
		}
		user, err := approvalWebAuthnUser(ctx, tx, userID, binding.CredentialID)
		if err != nil {
			return nil, err
		}
		options, session, err := s.webAuthn.BeginLogin(user, webauthnlib.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return nil, err
		}
		expiry := time.Now().Add(approvalTTL)
		session.Expires = expiry
		challenge, err := tx.AuthStore().BeginChallenge(ctx, "approval", userID, session.Challenge, expiry, approvalChallenge{binding, session})
		if err != nil {
			return nil, err
		}
		cleanup = challenge
		return gin.H{"challengeId": challenge.ID, "challenge": session.Challenge, "options": options, "keyProtection": binding.KeyProtection, "wrappedKeyEpoch": binding.CredentialEpoch}, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	err = s.deleteQueue.Enqueue(deleteEvent{KeyName: "challenge-delete:" + cleanup.ID, Kind: "challenge", ID: cleanup.ID, TTL: cleanup.ExpiresAt.Add(10 * time.Minute)})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) RouteV2AuthApprovalFinish(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}
	var req struct {
		ChallengeID string          `json:"challengeId"`
		Credential  json.RawMessage `json:"credential"`
	}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, approvalDenied())
		return
	}
	var cleanup *db.AuthChallenge
	grantID, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (string, error) {
		var payload approvalChallenge
		err := tx.AuthStore().ConsumeChallenge(ctx, req.ChallengeID, "approval", userID, &payload)
		if err != nil || payload.Session == nil {
			return "", approvalDenied()
		}
		binding, err := s.approvalIdentity(ctx, tx, userID, payload.Binding.CredentialID, payload.Binding.State, payload.Binding.Action)
		if err != nil {
			return "", err
		}
		if binding != payload.Binding || payload.Session.UserVerification != protocol.VerificationRequired {
			return "", approvalDenied()
		}
		user, err := approvalWebAuthnUser(ctx, tx, userID, binding.CredentialID)
		if err != nil {
			return "", err
		}
		request, err := newJSONHTTPRequest(c, req.Credential)
		if err != nil {
			return "", approvalDenied()
		}
		credential, err := s.webAuthn.FinishLogin(user, *payload.Session, request)
		if err != nil {
			return "", approvalDenied()
		}
		if credential.Authenticator.CloneWarning || base64.RawURLEncoding.EncodeToString(credential.ID) != binding.CredentialID {
			return "", approvalDenied()
		}
		err = s.validateAuthenticatorSignCount(c, user, credential)
		if err != nil {
			return "", err
		}
		err = tx.AuthStore().UpdateCredentialSignCount(ctx, userID, binding.CredentialID, credential.Authenticator.SignCount)
		if err != nil {
			return "", err
		}
		if binding.State == "" && binding.Action == "" {
			return "", nil
		}
		grant, err := tx.AuthStore().BeginChallenge(ctx, "approval-grant", userID, payload.Session.Challenge, time.Now().Add(approvalTTL), binding)
		if err != nil {
			return "", err
		}
		cleanup = grant
		return grant.ID, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if cleanup != nil {
		err = s.deleteQueue.Enqueue(deleteEvent{KeyName: "challenge-delete:" + cleanup.ID, Kind: "challenge", ID: cleanup.ID, TTL: cleanup.ExpiresAt.Add(10 * time.Minute)})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"grantId": grantID})
}

// Consume inside the same transaction as the authorized write
func (s *Server) consumeApprovalGrant(c *gin.Context, tx *db.DbTx, userID, grantID, state, action, targetCredentialID string) (approvalBinding, error) {
	if userID == "" || grantID == "" || (state == "" && action == "") {
		return approvalBinding{}, approvalDenied()
	}
	var binding approvalBinding
	err := tx.AuthStore().ConsumeChallenge(c.Request.Context(), grantID, "approval-grant", userID, &binding)
	if err != nil {
		return approvalBinding{}, approvalDenied()
	}
	if action == "update-wrapped-key" && (targetCredentialID == "" || binding.CredentialID != targetCredentialID) {
		return approvalBinding{}, approvalDenied()
	}
	if action != "update-wrapped-key" && targetCredentialID != "" {
		return approvalBinding{}, approvalDenied()
	}
	if binding.State != state || binding.Action != action {
		return approvalBinding{}, approvalDenied()
	}
	current, err := s.approvalIdentity(c.Request.Context(), tx, userID, binding.CredentialID, state, action)
	if err != nil {
		return approvalBinding{}, err
	}
	if current != binding {
		return approvalBinding{}, approvalDenied()
	}
	return binding, nil
}

func approvalWebAuthnUser(ctx context.Context, tx *db.DbTx, userID, credentialID string) (*v2WebAuthnUser, error) {
	user, err := tx.AuthStore().GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	waUser, err := loadWebAuthnUser(ctx, tx.AuthStore(), user)
	if err != nil {
		return nil, err
	}
	if waUser == nil {
		return nil, approvalDenied()
	}
	selected := make([]webauthnlib.Credential, 0, 1)
	for _, candidate := range waUser.credentials {
		if base64.RawURLEncoding.EncodeToString(candidate.ID) == credentialID {
			selected = append(selected, candidate)
		}
	}
	if len(selected) != 1 {
		return nil, approvalDenied()
	}
	waUser.credentials = selected
	return waUser, nil
}
