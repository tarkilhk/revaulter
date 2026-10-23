package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/stretchr/testify/require"
)

func approvalFixture(t *testing.T) (*Server, *testPasskey, string) {
	t.Helper()
	setTestConfig(t, "approval.db")
	s := newTestServer(t, nil, nil, nil)
	s.webAuthn = newTestWebAuthn(t)
	pk := newTestPasskey(t, webauthncose.AlgES256)
	user, err := newV2WebAuthnUserForRegistration("approval-user", "Approval")
	require.NoError(t, err)
	creation, session, err := s.beginWebAuthnSession(user, "bitwarden")
	require.NoError(t, err)
	cred, err := s.webAuthn.FinishRegistration(user, *session, newTestJSONRequest(t, pk.attestationResponse(t, creation.Response.Challenge.String())))
	require.NoError(t, err)
	encoded, err := json.Marshal(cred)
	require.NoError(t, err)
	id := base64.RawURLEncoding.EncodeToString(pk.credentialID)
	_, err = db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (any, error) {
		_, e := tx.AuthStore().RegisterUser(ctx, db.RegisterUserInput{UserID: "approval-user", WebAuthnUserID: base64.RawURLEncoding.EncodeToString(user.id), CredentialID: id, PublicKey: string(encoded)})
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE v2_users SET ready=true WHERE id='approval-user'`)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE v2_user_credentials SET wrapped_key_epoch=1, key_protection='bitwarden' WHERE user_id='approval-user'`)
		return nil, e
	})
	require.NoError(t, err)
	return s, pk, id
}

func approvalCall(t *testing.T, handler gin.HandlerFunc, body any) (int, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encoded))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("location", &url.URL{Scheme: "https", Host: "example.com"})
	c.Set(contextKeyUserID, "approval-user")
	c.Set(contextKeySessionDigest, "test-session-digest")
	handler(c)
	var result map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	return w.Code, result
}

func approvalAssertion(t *testing.T, pk *testPasskey, challenge string) json.RawMessage {
	t.Helper()
	var payload map[string]any
	err := json.Unmarshal(pk.assertionResponse(t, challenge, nil), &payload)
	require.NoError(t, err)
	delete(payload, "clientExtensionResults")
	return marshalTestJSON(t, payload)
}

func TestApprovalServerChallengeAndSingleUseGrant(t *testing.T) {
	s, pk, id := approvalFixture(t)
	code, begin := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id, "action": "update-wrapped-key"})
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "bitwarden", begin["keyProtection"])
	assertion := approvalAssertion(t, pk, approvalTestString(t, begin["challenge"]))
	code, finish := approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": assertion})
	require.Equal(t, http.StatusOK, code, finish)
	grant := approvalTestString(t, finish["grantId"])
	require.NotEmpty(t, grant)
	code, _ = approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": assertion})
	require.Equal(t, http.StatusForbidden, code)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Set(contextKeySessionDigest, "test-session-digest")
	_, err := db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (any, error) {
		return s.consumeApprovalGrant(c, tx, "another-user", grant, "", "update-wrapped-key", id)
	})
	require.Error(t, err)
	consume := func(target string, rollback bool) error {
		_, err := db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (any, error) {
			_, err := s.consumeApprovalGrant(c, tx, "approval-user", grant, "", "update-wrapped-key", target)
			if err != nil {
				return nil, err
			}
			if rollback {
				return nil, errors.New("write failed")
			}
			return nil, nil
		})
		return err
	}
	err = consume("foreign", false)
	require.Error(t, err)
	err = consume(id, true)
	require.Error(t, err)
	err = consume(id, false)
	require.NoError(t, err)
	err = consume(id, false)
	require.Error(t, err)
}

func TestApprovalRejectsChangedChallengeAndPurpose(t *testing.T) {
	s, pk, id := approvalFixture(t)
	code, _ := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id, "state": "x", "action": "add-credential"})
	require.Equal(t, http.StatusForbidden, code)
	code, begin := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id})
	require.Equal(t, http.StatusOK, code)
	code, _ = approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": approvalAssertion(t, pk, "different-challenge")})
	require.Equal(t, http.StatusForbidden, code)
	code, result := approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": approvalAssertion(t, pk, approvalTestString(t, begin["challenge"]))})
	require.Equal(t, http.StatusOK, code, result)
	require.Empty(t, result["grantId"])
}

func TestApprovalRejectsRevocationEpochAndExpiry(t *testing.T) {
	for _, change := range []string{
		`DELETE FROM v2_user_credentials WHERE user_id='approval-user'`,
		`UPDATE v2_users SET wrapped_key_epoch=2 WHERE id='approval-user'`,
		`UPDATE v2_user_credentials SET key_protection='prf' WHERE user_id='approval-user'`,
		`UPDATE v2_users SET status='disabled' WHERE id='approval-user'`,
		`UPDATE v2_auth_challenges SET expires_at=1`,
	} {
		t.Run(change, func(t *testing.T) {
			s, pk, id := approvalFixture(t)
			code, begin := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id, "action": "add-credential"})
			require.Equal(t, http.StatusOK, code)
			_, err := s.db.Exec(t.Context(), change)
			require.NoError(t, err)
			code, _ = approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": approvalAssertion(t, pk, approvalTestString(t, begin["challenge"]))})
			require.Equal(t, http.StatusForbidden, code)
		})
	}
}

func TestApprovalRejectsMissingUVWithValidSignature(t *testing.T) {
	s, pk, id := approvalFixture(t)
	code, begin := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id, "action": "add-credential"})
	require.Equal(t, http.StatusOK, code)
	var assertion map[string]any
	err := json.Unmarshal(approvalAssertion(t, pk, approvalTestString(t, begin["challenge"])), &assertion)
	require.NoError(t, err)
	response, ok := assertion["response"].(map[string]any)
	require.True(t, ok)
	authData, err := base64.RawURLEncoding.DecodeString(approvalTestString(t, response["authenticatorData"]))
	require.NoError(t, err)
	authData[32] &^= testFlagUserVerified
	clientData, err := base64.RawURLEncoding.DecodeString(approvalTestString(t, response["clientDataJSON"]))
	require.NoError(t, err)
	hash := sha256.Sum256(clientData)
	signature, err := pk.sign(append(authData, hash[:]...))
	require.NoError(t, err)
	response["authenticatorData"] = base64.RawURLEncoding.EncodeToString(authData)
	response["signature"] = base64.RawURLEncoding.EncodeToString(signature)
	code, _ = approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": assertion})
	require.Equal(t, http.StatusForbidden, code)
}

// Existing business-logic tests seed a grant explicitly; ceremony tests above exercise actual signed assertions
func seedTestApprovalGrant(t *testing.T, s *Server, userID, state, action, credentialID, sessionToken string) string {
	t.Helper()
	id, err := db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (string, error) {
		if credentialID == "" {
			credentials, err := tx.AuthStore().ListCredentials(ctx, userID)
			if err != nil {
				return "", err
			}
			if len(credentials) == 0 {
				return "", errors.New("missing test credential")
			}
			credentialID = credentials[0].CredentialID
		}
		binding, err := s.approvalIdentity(ctx, tx, userID, credentialID, state, action)
		if err != nil {
			return "", err
		}
		leaseID := ""
		if state != "" {
			lease, leaseErr := s.issueUnlockLease(ctx, tx, userID, credentialID, approvalDigest(sessionToken), time.Now())
			if leaseErr != nil {
				return "", leaseErr
			}
			leaseID = lease.ID
		}
		grant, err := tx.AuthStore().BeginChallenge(ctx, "approval-grant", userID, "test-only-grant", time.Now().Add(approvalTTL), approvalGrant{Binding: binding, LeaseID: leaseID})
		if err != nil {
			return "", err
		}
		return grant.ID, nil
	})
	require.NoError(t, err)
	return id
}

func TestApprovalRequestGrantRejectsChangedBinding(t *testing.T) {
	for _, change := range []string{
		`UPDATE v2_requests SET encrypted_request='changed ciphertext and client key' WHERE state='approval-state'`,
		`UPDATE v2_requests SET status='canceled' WHERE state='approval-state'`,
		`UPDATE v2_requests SET expires_at=1 WHERE state='approval-state'`,
		`DELETE FROM v2_user_credentials WHERE user_id='approval-user'`,
		`UPDATE v2_users SET wrapped_key_epoch=2 WHERE id='approval-user'`,
		`UPDATE v2_auth_challenges SET expires_at=1 WHERE kind='approval-grant'`,
	} {
		t.Run(change, func(t *testing.T) {
			s, pk, id := approvalFixture(t)
			err := s.db.RequestStore().CreateRequest(t.Context(), db.CreateRequestInput{State: "approval-state", UserID: "approval-user", Operation: "decrypt", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), EncryptedRequest: `{"ciphertext":"dummy","cliEphemeralPublicKey":"dummy"}`})
			require.NoError(t, err)
			code, begin := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id, "state": "approval-state"})
			require.Equal(t, http.StatusOK, code, begin)
			code, finish := approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": approvalAssertion(t, pk, approvalTestString(t, begin["challenge"]))})
			require.Equal(t, http.StatusOK, code, finish)
			_, err = s.db.Exec(t.Context(), change)
			require.NoError(t, err)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			c.Set(contextKeySessionDigest, "test-session-digest")
			_, err = db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (any, error) {
				return s.consumeApprovalGrant(c, tx, "approval-user", approvalTestString(t, finish["grantId"]), "approval-state", "", "")
			})
			require.Error(t, err)
		})
	}
}

func TestApprovalCredentialEnrollmentRejectsRevokedApprover(t *testing.T) {
	s, _, id := approvalFixture(t)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Set(contextKeySessionDigest, "test-session-digest")
	grant := seedTestApprovalGrant(t, s, "approval-user", "", "add-credential", id, "")
	begin, err := db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (addCredentialBeginRes, error) {
		binding, err := s.consumeApprovalGrant(c, tx, "approval-user", grant, "", "add-credential", "")
		if err != nil {
			return addCredentialBeginRes{}, err
		}
		return s.addCredentialBegin(ctx, tx, "approval-user", &v2AuthAddCredentialBeginRequest{KeyProtection: "bitwarden", approver: &binding})
	})
	require.NoError(t, err)
	_, err = s.db.Exec(t.Context(), `DELETE FROM v2_user_credentials WHERE user_id='approval-user'`)
	require.NoError(t, err)
	_, err = db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (addCredentialFinishRes, error) {
		return s.addCredentialFinish(c, tx, addCredentialFinishVals{userID: "approval-user", req: &v2AuthAddCredentialFinishRequest{ChallengeID: begin.challenge.ID}})
	})
	require.ErrorContains(t, err, "Fresh approval")
}

func TestApprovalAllowsExistingStaleWrapper(t *testing.T) {
	s, pk, id := approvalFixture(t)
	_, err := s.db.Exec(t.Context(), `UPDATE v2_users SET wrapped_key_epoch=2 WHERE id='approval-user'`)
	require.NoError(t, err)
	code, begin := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id})
	require.Equal(t, http.StatusOK, code)
	challenge := approvalTestString(t, begin["challenge"])
	assertion := approvalAssertion(t, pk, challenge)
	code, _ = approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": assertion})
	require.Equal(t, http.StatusOK, code)
}

func approvalTestString(t *testing.T, value any) string {
	t.Helper()
	text, ok := value.(string)
	require.True(t, ok)
	return text
}

func TestApprovalConcurrentRequestCommit(t *testing.T) {
	s, pk, id := approvalFixture(t)
	err := s.db.RequestStore().CreateRequest(t.Context(), db.CreateRequestInput{State: "approval-state", UserID: "approval-user", Operation: "decrypt", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), EncryptedRequest: `{"ciphertext":"dummy"}`})
	require.NoError(t, err)
	code, begin := approvalCall(t, s.RouteV2AuthApprovalBegin, gin.H{"credentialId": id, "state": "approval-state"})
	require.Equal(t, http.StatusOK, code)
	assertion := approvalAssertion(t, pk, approvalTestString(t, begin["challenge"]))
	code, finish := approvalCall(t, s.RouteV2AuthApprovalFinish, gin.H{"challengeId": begin["challengeId"], "credential": assertion})
	require.Equal(t, http.StatusOK, code)
	grant := approvalTestString(t, finish["grantId"])
	commit := func(state string) error {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Set(contextKeySessionDigest, "test-session-digest")
		_, commitErr := db.ExecuteInTransaction(t.Context(), s.db, 5*time.Second, func(ctx context.Context, tx *db.DbTx) (any, error) {
			_, consumeErr := s.consumeApprovalGrant(c, tx, "approval-user", grant, state, "", "")
			if consumeErr != nil {
				return nil, consumeErr
			}
			return tx.RequestStore().CompleteRequest(ctx, state, "approval-user", protocolv2.ResponseEnvelope{Ciphertext: "dummy"})
		})
		return commitErr
	}
	err = commit("other-request")
	require.Error(t, err)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() { <-start; results <- commit("approval-state") }()
	}
	close(start)
	succeeded := 0
	for range 2 {
		if <-results == nil {
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded)
	record, err := s.db.RequestStore().GetRequest(t.Context(), "approval-state")
	require.NoError(t, err)
	require.Equal(t, db.V2RequestStatusCompleted, record.Status)
}
