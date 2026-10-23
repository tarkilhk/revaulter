package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/stretchr/testify/require"
)

func testUnlockLease(t *testing.T, s *Server) string {
	t.Helper()
	records, err := s.db.AuthStore().ListCredentials(t.Context(), "approval-user")
	require.NoError(t, err)
	lease, err := db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (*db.AuthChallenge, error) {
		return s.issueUnlockLease(ctx, tx, "approval-user", records[0].CredentialID, "test-session-digest", time.Now())
	})
	require.NoError(t, err)
	return lease.ID
}

func leaseRequest(t *testing.T, s *Server, state string) {
	t.Helper()
	err := s.db.RequestStore().CreateRequest(t.Context(), db.CreateRequestInput{State: state, UserID: "approval-user", Operation: "decrypt", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), EncryptedRequest: `{"ciphertext":"synthetic"}`})
	require.NoError(t, err)
}

func leaseContext(digest string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Set(contextKeyUserID, "approval-user")
	c.Set(contextKeySessionDigest, digest)
	return c
}

func TestUnlockLeaseWindowAndSessionBinding(t *testing.T) {
	s, _, _ := approvalFixture(t)
	lease := testUnlockLease(t, s)
	leaseRequest(t, s, "first")
	leaseRequest(t, s, "second")
	for _, state := range []string{"first", "second"} {
		code, result := approvalCall(t, s.RouteV2AuthApprovalGrant, gin.H{"leaseId": lease, "state": state})
		require.Equal(t, http.StatusOK, code, result)
		require.NotEmpty(t, result["grantId"])
	}
	var leaseExpiry, grantExpiry int64
	err := s.db.QueryRow(t.Context(), `SELECT expires_at FROM v2_auth_challenges WHERE id=$1`, lease).Scan(&leaseExpiry)
	require.NoError(t, err)
	err = s.db.QueryRow(t.Context(), `SELECT MAX(expires_at) FROM v2_auth_challenges WHERE kind='approval-grant'`).Scan(&grantExpiry)
	require.NoError(t, err)
	require.Equal(t, leaseExpiry, grantExpiry)
	_, err = db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (unlockLease, error) {
		return s.validateUnlockLease(leaseContext("different-session"), tx, "approval-user", lease)
	})
	require.Error(t, err)
}

func TestUnlockLeaseParentRecheckedAtConfirm(t *testing.T) {
	for _, change := range []string{
		`UPDATE v2_auth_challenges SET expires_at=1 WHERE kind='unlock-lease'`,
		`UPDATE v2_auth_challenges SET used_at=1 WHERE kind='unlock-lease'`,
		`DELETE FROM v2_user_credentials WHERE user_id='approval-user'`,
		`UPDATE v2_users SET wrapped_key_epoch=2 WHERE id='approval-user'`,
		`UPDATE v2_user_credentials SET wrapped_key_epoch=2 WHERE user_id='approval-user'`,
		`UPDATE v2_user_credentials SET key_protection='prf' WHERE user_id='approval-user'`,
		`UPDATE v2_requests SET encrypted_request='changed' WHERE state='request'`,
	} {
		t.Run(change, func(t *testing.T) {
			s, _, _ := approvalFixture(t)
			lease := testUnlockLease(t, s)
			leaseRequest(t, s, "request")
			code, result := approvalCall(t, s.RouteV2AuthApprovalGrant, gin.H{"leaseId": lease, "state": "request"})
			require.Equal(t, http.StatusOK, code)
			grant, ok := result["grantId"].(string)
			require.True(t, ok)
			_, err := s.db.Exec(t.Context(), change)
			require.NoError(t, err)
			_, err = db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (approvalBinding, error) {
				return s.consumeApprovalGrant(leaseContext("test-session-digest"), tx, "approval-user", grant, "request", "", "")
			})
			require.Error(t, err)
		})
	}
}

func TestUnlockLeaseLogoutInvalidatesChildren(t *testing.T) {
	s, _, _ := approvalFixture(t)
	lease := testUnlockLease(t, s)
	leaseRequest(t, s, "request")
	code, result := approvalCall(t, s.RouteV2AuthApprovalGrant, gin.H{"leaseId": lease, "state": "request"})
	require.Equal(t, http.StatusOK, code)
	grant, ok := result["grantId"].(string)
	require.True(t, ok)
	code, _ = approvalCall(t, s.RouteV2AuthLogout, gin.H{})
	require.Equal(t, http.StatusOK, code)
	_, err := db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (approvalBinding, error) {
		return s.consumeApprovalGrant(leaseContext("test-session-digest"), tx, "approval-user", grant, "request", "", "")
	})
	require.Error(t, err)
	code, _ = approvalCall(t, s.RouteV2AuthApprovalGrant, gin.H{"leaseId": lease, "state": "request"})
	require.Equal(t, http.StatusForbidden, code)
}

func TestUnlockLeaseGrantConcurrentOneUse(t *testing.T) {
	s, _, _ := approvalFixture(t)
	lease := testUnlockLease(t, s)
	leaseRequest(t, s, "request")
	code, result := approvalCall(t, s.RouteV2AuthApprovalGrant, gin.H{"leaseId": lease, "state": "request"})
	require.Equal(t, http.StatusOK, code)
	grant, ok := result["grantId"].(string)
	require.True(t, ok)
	results := make(chan error, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			_, err := db.ExecuteInTransaction(t.Context(), s.db, 5*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.V2RequestRecord, error) {
				_, err := s.consumeApprovalGrant(leaseContext("test-session-digest"), tx, "approval-user", grant, "request", "", "")
				if err != nil {
					return nil, err
				}
				return tx.RequestStore().CompleteRequest(ctx, "request", "approval-user", protocolv2.ResponseEnvelope{Ciphertext: "dummy"})
			})
			results <- err
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	record, err := s.db.RequestStore().GetRequest(t.Context(), "request")
	require.NoError(t, err)
	require.Equal(t, db.V2RequestStatusCompleted, record.Status)
}

func TestUnlockLeaseNoDelayedUVRenewal(t *testing.T) {
	s, _, id := approvalFixture(t)
	sess := &authSessionToken{UserID: "approval-user", Ready: true, VerifiedCredentialID: id, VerifiedAt: time.Now().Add(-approvalTTL - time.Second).Unix()}
	result, err := s.sessionUnlockLease(leaseContext("test-session-digest"), sess, &approvalBinding{})
	require.NoError(t, err)
	require.Empty(t, result.UnlockLeaseID)
}

func TestUnlockLeaseCookieBindingAndOriginalUVDeadline(t *testing.T) {
	s, _, id := approvalFixture(t)
	user, err := s.db.AuthStore().GetUserByID(t.Context(), "approval-user")
	require.NoError(t, err)
	first, err := newAuthSessionToken(user, time.Hour)
	require.NoError(t, err)
	second, err := newAuthSessionToken(user, time.Hour)
	require.NoError(t, err)
	require.NotEqual(t, first.SessionID, second.SessionID)
	first.VerifiedCredentialID = id
	first.VerifiedAt = time.Now().Add(-time.Minute).Unix()
	c := leaseContext("")
	c.Set("location", &url.URL{Scheme: "https", Host: "example.com"})
	err = setSessionCookie(c, first)
	require.NoError(t, err)
	cookies := (&http.Response{Header: c.Writer.Header()}).Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, approvalDigest(cookies[0].Value), c.GetString(contextKeySessionDigest))
	parsed, err := parseAuthSessionToken(cookies[0].Value)
	require.NoError(t, err)
	require.Equal(t, first.VerifiedAt, parsed.VerifiedAt)
	binding, err := db.ExecuteInTransaction(t.Context(), s.db, time.Second, func(ctx context.Context, tx *db.DbTx) (approvalBinding, error) {
		return s.approvalIdentity(ctx, tx, user.ID, id, "", "")
	})
	require.NoError(t, err)
	response, err := s.sessionUnlockLease(c, parsed, &binding)
	require.NoError(t, err)
	require.NotEmpty(t, response.UnlockLeaseID)
	require.Equal(t, first.VerifiedAt+120, response.UnlockLeaseExpiresAt)
	_, err = s.db.Exec(t.Context(), `UPDATE v2_users SET wrapped_key_epoch=2 WHERE id='approval-user'`)
	require.NoError(t, err)
	_, err = s.sessionUnlockLease(c, parsed, &binding)
	require.Error(t, err)
}
