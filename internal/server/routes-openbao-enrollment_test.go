package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/stretchr/testify/require"
)

func enrollmentFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s, _, _ := approvalFixture(t)
	cfg := config.Get()
	cfg.OpenBaoEnrollmentPath = filepath.Join(t.TempDir(), "enrollment.json")
	cfg.OpenBaoURL = "https://bao.example"
	seedEnrollmentIdentity(t, s, "approval-user")
	return s, cfg.OpenBaoEnrollmentPath
}

func seedEnrollmentIdentity(t *testing.T, s *Server, userID string) {
	t.Helper()
	anchor := seedV2AnchorForUser(t, s, userID)
	user, err := s.db.AuthStore().GetUserByID(t.Context(), userID)
	require.NoError(t, err)
	jwk, err := protocolv2.ParseECP384PublicJWKCanonicalBody(anchor.Es384JWKBody)
	require.NoError(t, err)
	sigEs, sigMl := signPubkeyBundleV2(t, anchor, &protocolv2.PubkeyBundlePayloadV2{UserID: user.ID, RequestEncEcdhPubkey: user.RequestEncEcdhPubkey, RequestEncMlkemPubkey: user.RequestEncMlkemPubkey, AnchorEs384Crv: jwk.Crv, AnchorEs384Kty: jwk.Kty, AnchorEs384X: jwk.X, AnchorEs384Y: jwk.Y, AnchorMldsa87PublicKey: anchor.Mldsa87PubBase64, V: 2})
	_, err = s.db.Exec(t.Context(), `UPDATE v2_users SET pubkey_bundle_signature_es384=$1,pubkey_bundle_signature_mldsa87=$2,pubkey_bundle_version=2 WHERE id=$3`, sigEs, sigMl, user.ID)
	require.NoError(t, err)
}

func testEnrollmentEnvelope() openBaoEnvelope {
	return openBaoEnvelope{Kind: "revaulter/1", Algorithm: "A256GCM", KeyLabel: "openbao-unseal", Value: base64.RawURLEncoding.EncodeToString([]byte("synthetic ciphertext")), Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 12)), Tag: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
}

func enrollmentCall(s *Server, user, body string, get bool) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/v2/auth/openbao-enrollment", strings.NewReader(body))
	c.Set(contextKeyUserID, user)
	if get {
		s.RouteV2AuthOpenBaoEnrollmentStatus(c)
	} else {
		s.RouteV2AuthOpenBaoEnrollment(c)
	}
	return w
}

func TestOpenBaoEnrollmentSessionApprovalAndReplay(t *testing.T) {
	s, path := enrollmentFixture(t)
	grant := seedTestApprovalGrant(t, s, "approval-user", "", "enroll-openbao", "", "")
	body, err := json.Marshal(gin.H{"envelope": testEnrollmentEnvelope(), "approvalGrant": grant})
	require.NoError(t, err)
	for _, user := range []string{"", "other-user"} {
		response := enrollmentCall(s, user, string(body), false)
		require.Equal(t, http.StatusForbidden, response.Code)
	}
	response := enrollmentCall(s, "approval-user", string(body), false)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	first, err := os.ReadFile(path)
	require.NoError(t, err)
	stat, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), stat.Mode().Perm())
	var saved openBaoEnrollment
	err = json.Unmarshal(first, &saved)
	require.NoError(t, err)
	require.Equal(t, "approval-user", saved.UserID)
	require.Len(t, saved.Trust.Entries, 1)
	require.NotEmpty(t, saved.RequestKey)
	response = enrollmentCall(s, "approval-user", string(body), false)
	require.Equal(t, http.StatusForbidden, response.Code)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, first, after)
	status := enrollmentCall(s, "approval-user", "", true)
	require.Equal(t, http.StatusOK, status.Code)
	require.NotContains(t, status.Body.String(), saved.RequestKey)
	require.NotContains(t, status.Body.String(), saved.Envelope.Value)
}

func TestOpenBaoEnrollmentRejectsInvalidInput(t *testing.T) {
	s, path := enrollmentFixture(t)
	grant := seedTestApprovalGrant(t, s, "approval-user", "", "enroll-openbao", "", "")
	envelope, err := json.Marshal(testEnrollmentEnvelope())
	require.NoError(t, err)
	valid := `{"envelope":` + string(envelope) + `,"approvalGrant":"` + grant + `"}`
	cases := []string{
		strings.Replace(valid, `"envelope":`, `"shares":["plain"],"envelope":`, 1),
		strings.Replace(valid, `"kind":`, `"kind":"revaulter/1","kind":`, 1),
		valid + ` {}`,
		strings.Replace(valid, `"algorithm":"A256GCM"`, `"algorithm":"plain"`, 1),
		strings.Replace(valid, `"nonce":"AAAAAAAAAAAAAAAA"`, `"nonce":"bad"`, 1),
		`{"envelope":null,"approvalGrant":"` + grant + `"}`,
		strings.Repeat(" ", openBaoEnrollmentLimit) + valid,
	}
	for _, body := range cases {
		response := enrollmentCall(s, "approval-user", body, false)
		require.Equal(t, http.StatusBadRequest, response.Code)
	}
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
	response := enrollmentCall(s, "approval-user", valid, false)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
}

func TestOpenBaoEnrollmentExpiredWrongActionAndDisabled(t *testing.T) {
	s, _ := enrollmentFixture(t)
	for _, action := range []string{"enroll-openbao", "add-credential"} {
		grant := seedTestApprovalGrant(t, s, "approval-user", "", action, "", "")
		if action == "enroll-openbao" {
			_, err := s.db.Exec(t.Context(), `UPDATE v2_auth_challenges SET expires_at=1 WHERE id=$1`, grant)
			require.NoError(t, err)
		}
		body, err := json.Marshal(gin.H{"envelope": testEnrollmentEnvelope(), "approvalGrant": grant})
		require.NoError(t, err)
		response := enrollmentCall(s, "approval-user", string(body), false)
		require.Equal(t, http.StatusForbidden, response.Code)
	}
	config.Get().OpenBaoEnrollmentPath = ""
	response := enrollmentCall(s, "approval-user", `{}`, false)
	require.Equal(t, http.StatusForbidden, response.Code)
	response = enrollmentCall(s, "approval-user", "", true)
	require.JSONEq(t, `{"enabled":false,"enrolled":false,"target":"","requestKeyEnabled":false}`, response.Body.String())
}

func TestOpenBaoEnrollmentAtomicWriteFailurePreservesPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	bundle := &openBaoEnrollment{Version: 1, UserID: "owner", Envelope: testEnrollmentEnvelope()}
	err := writeOpenBaoEnrollment(path, bundle)
	require.NoError(t, err)
	previous, err := os.ReadFile(path)
	require.NoError(t, err)
	// A failed temporary write must leave the already published bundle intact
	// Root bypasses directory permissions, so this fault injection applies to ordinary users
	if os.Geteuid() != 0 {
		err = os.Chmod(filepath.Dir(path), 0o500)
		require.NoError(t, err)
		err = writeOpenBaoEnrollment(path, bundle)
		restoreErr := os.Chmod(filepath.Dir(path), 0o700)
		require.NoError(t, restoreErr)
		require.Error(t, err)
	}
	// A rename to an existing directory must fail without replacing its contents
	badTarget := filepath.Join(filepath.Dir(path), "existing")
	err = os.Mkdir(badTarget, 0o700)
	require.NoError(t, err)
	err = writeOpenBaoEnrollment(badTarget, bundle)
	require.Error(t, err)
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, bytes.Equal(previous, current))
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".openbao-enrollment-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestOpenBaoEnrollmentAnyReadyUserCanReplaceWithOwnApproval(t *testing.T) {
	s, path := enrollmentFixture(t)
	_, other := seedV2SessionCookie(t, s, "other-user", "Other")
	seedEnrollmentIdentity(t, s, other.ID)
	_, err := s.db.Exec(t.Context(), `UPDATE v2_user_credentials SET key_protection='bitwarden' WHERE user_id=$1`, other.ID)
	require.NoError(t, err)
	response := enrollmentCall(s, other.ID, "", true)
	require.Equal(t, http.StatusOK, response.Code)
	for _, userID := range []string{"approval-user", other.ID} {
		grant := seedTestApprovalGrant(t, s, userID, "", "enroll-openbao", "", "")
		envelope := testEnrollmentEnvelope()
		envelope.Value = base64.RawURLEncoding.EncodeToString([]byte("synthetic ciphertext for " + userID))
		body, marshalErr := json.Marshal(gin.H{"envelope": envelope, "approvalGrant": grant})
		require.NoError(t, marshalErr)
		wrongUser := "approval-user"
		if userID == wrongUser {
			wrongUser = other.ID
		}
		response = enrollmentCall(s, wrongUser, string(body), false)
		require.Equal(t, http.StatusForbidden, response.Code)
		response = enrollmentCall(s, userID, string(body), false)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		saved, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		var bundle openBaoEnrollment
		decodeErr := json.Unmarshal(saved, &bundle)
		require.NoError(t, decodeErr)
		require.Equal(t, userID, bundle.UserID)
		require.Equal(t, envelope, bundle.Envelope)
		currentUser, userErr := s.db.AuthStore().GetUserByID(t.Context(), userID)
		require.NoError(t, userErr)
		require.Equal(t, currentUser.RequestKey, bundle.RequestKey)
		require.Contains(t, bundle.Trust.Entries, strings.TrimRight(config.Get().BaseUrl, "/")+"|"+userID)
		response = enrollmentCall(s, userID, string(body), false)
		require.Equal(t, http.StatusForbidden, response.Code)
		response = enrollmentCall(s, wrongUser, "", true)
		require.Equal(t, http.StatusOK, response.Code)
		require.NotContains(t, response.Body.String(), bundle.RequestKey)
		require.NotContains(t, response.Body.String(), bundle.UserID)
	}
}

func TestOpenBaoEnrollmentRequestKeyPrerequisite(t *testing.T) {
	s, path := enrollmentFixture(t)
	previous := &openBaoEnrollment{Version: 1, UserID: "previous-user", Target: config.Get().OpenBaoURL, Envelope: testEnrollmentEnvelope()}
	err := writeOpenBaoEnrollment(path, previous)
	require.NoError(t, err)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	user, err := s.db.AuthStore().GetUserByID(t.Context(), "approval-user")
	require.NoError(t, err)
	err = s.db.AuthStore().UpdateRequestAuthMethods(t.Context(), user.ID, db.RequestAuthMethods{RequestKey: false, OIDC: true})
	require.NoError(t, err)
	response := enrollmentCall(s, user.ID, "", true)
	require.Equal(t, http.StatusOK, response.Code)
	var status map[string]any
	err = json.Unmarshal(response.Body.Bytes(), &status)
	require.NoError(t, err)
	require.Equal(t, false, status["requestKeyEnabled"])
	require.Equal(t, true, status["enrolled"])
	grant := seedTestApprovalGrant(t, s, user.ID, "", "enroll-openbao", "", "")
	body, err := json.Marshal(gin.H{"envelope": testEnrollmentEnvelope(), "approvalGrant": grant})
	require.NoError(t, err)
	response = enrollmentCall(s, user.ID, string(body), false)
	require.Equal(t, http.StatusConflict, response.Code)
	require.Contains(t, response.Body.String(), "Enable Request key authentication before enrolling OpenBao")
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	unchanged, err := s.db.AuthStore().GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.False(t, unchanged.RequestAuthMethods.RequestKey)
	require.Equal(t, user.RequestKey, unchanged.RequestKey)
	err = s.db.AuthStore().UpdateRequestAuthMethods(t.Context(), user.ID, db.RequestAuthMethods{RequestKey: true, OIDC: true})
	require.NoError(t, err)
	response = enrollmentCall(s, user.ID, "", true)
	require.Equal(t, http.StatusOK, response.Code)
	err = json.Unmarshal(response.Body.Bytes(), &status)
	require.NoError(t, err)
	require.Equal(t, true, status["requestKeyEnabled"])
	// The failed transaction did not consume the approval grant
	response = enrollmentCall(s, user.ID, string(body), false)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	response = enrollmentCall(s, user.ID, string(body), false)
	require.Equal(t, http.StatusForbidden, response.Code)
}
