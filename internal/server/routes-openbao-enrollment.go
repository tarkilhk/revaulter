package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
)

const openBaoEnrollmentLimit = 16 << 10

var openBaoEnrollmentMu sync.Mutex

type openBaoEnvelope struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	KeyLabel  string `json:"keyLabel"`
	Value     string `json:"value"`
	Nonce     string `json:"nonce"`
	Tag       string `json:"tag"`
}

type openBaoEnrollment struct {
	Version    int                   `json:"version"`
	UserID     string                `json:"userId"`
	Target     string                `json:"target"`
	Envelope   openBaoEnvelope       `json:"envelope"`
	RequestKey string                `json:"requestKey"`
	Trust      clientcore.TrustStore `json:"trust"`
	UpdatedAt  time.Time             `json:"updatedAt"`
}

func openBaoEnrollmentEnabled() bool {
	cfg := config.Get()
	return filepath.IsAbs(cfg.OpenBaoEnrollmentPath) && validEnrollmentOrigin(cfg.OpenBaoURL) && validEnrollmentOrigin(cfg.BaseUrl)
}

func validEnrollmentOrigin(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery
}

// Enrollment status is available to every active account with completed setup
func readOpenBaoEnrollment(ctx context.Context, tx *db.DbTx, path, userID string) (*openBaoEnrollment, error) {
	if userID == "" {
		return nil, approvalDenied()
	}
	user, err := tx.AuthStore().GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil || !user.Ready || user.Status != "active" {
		return nil, approvalDenied()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, NewResponseError(http.StatusInternalServerError, "Enrollment is unavailable")
	}
	var bundle openBaoEnrollment
	err = strictEnrollmentJSON(data, &bundle)
	if err != nil || bundle.Version != 1 || bundle.UserID == "" || bundle.Target != strings.TrimRight(config.Get().OpenBaoURL, "/") || !bundle.Envelope.valid() {
		return nil, NewResponseError(http.StatusInternalServerError, "Enrollment is unavailable")
	}
	return &bundle, nil
}

func (s *Server) RouteV2AuthOpenBaoEnrollmentStatus(c *gin.Context) {
	if !openBaoEnrollmentEnabled() {
		c.JSON(http.StatusOK, gin.H{"enabled": false, "enrolled": false, "target": "", "requestKeyEnabled": false})
		return
	}
	openBaoEnrollmentMu.Lock()
	defer openBaoEnrollmentMu.Unlock()
	requestKeyEnabled := false
	bundle, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (*openBaoEnrollment, error) {
		user, readErr := tx.AuthStore().GetUserByID(ctx, c.GetString(contextKeyUserID))
		if readErr != nil {
			return nil, readErr
		}
		if user != nil {
			requestKeyEnabled = user.RequestAuthMethods.RequestKey
		}
		return readOpenBaoEnrollment(ctx, tx, config.Get().OpenBaoEnrollmentPath, c.GetString(contextKeyUserID))
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	status := gin.H{"enabled": true, "enrolled": bundle != nil, "requestKeyEnabled": requestKeyEnabled, "target": strings.TrimRight(config.Get().OpenBaoURL, "/")}
	if bundle != nil {
		status["updatedAt"] = bundle.UpdatedAt
	}
	c.JSON(http.StatusOK, status)
}

func (s *Server) RouteV2AuthOpenBaoEnrollment(c *gin.Context) {
	cfg := config.Get()
	userID := c.GetString(contextKeyUserID)
	if !openBaoEnrollmentEnabled() || userID == "" {
		AbortWithErrorJSON(c, approvalDenied())
		return
	}
	var req struct {
		Envelope      openBaoEnvelope `json:"envelope"`
		ApprovalGrant string          `json:"approvalGrant"`
	}
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, openBaoEnrollmentLimit+1))
	if err == nil && len(data) <= openBaoEnrollmentLimit {
		err = strictEnrollmentJSON(data, &req)
		if err == nil {
			var shape map[string]json.RawMessage
			err = json.Unmarshal(data, &shape)
			if err == nil && (len(shape) != 2 || shape["envelope"] == nil || shape["approvalGrant"] == nil) {
				err = errors.New("invalid enrollment fields")
			}
			if err == nil {
				var envelopeFields map[string]json.RawMessage
				err = json.Unmarshal(shape["envelope"], &envelopeFields)
				if err == nil {
					if len(envelopeFields) != 6 {
						err = errors.New("invalid envelope fields")
					}
					for _, key := range []string{"kind", "algorithm", "keyLabel", "value", "nonce", "tag"} {
						if envelopeFields[key] == nil {
							err = errors.New("invalid envelope fields")
						}
					}
				}
			}
		}
	} else {
		err = errors.New("invalid size")
	}
	if err != nil || !req.Envelope.valid() || req.ApprovalGrant == "" || len(req.ApprovalGrant) > 256 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid encrypted enrollment"))
		return
	}
	openBaoEnrollmentMu.Lock()
	defer openBaoEnrollmentMu.Unlock()

	// Commit consumption before file publication so a failed database commit can never publish a replayable grant
	bundle, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (*openBaoEnrollment, error) {
		_, grantErr := s.consumeApprovalGrant(c, tx, userID, req.ApprovalGrant, "", "enroll-openbao", "")
		if grantErr != nil {
			return nil, grantErr
		}
		user, readErr := tx.AuthStore().GetUserByID(ctx, userID)
		if readErr != nil {
			return nil, readErr
		}
		if user == nil || user.RequestKey == "" {
			return nil, approvalDenied()
		}
		if !user.RequestAuthMethods.RequestKey {
			return nil, NewResponseError(http.StatusConflict, "Enable Request key authentication before enrolling OpenBao")
		}
		trust := clientcore.TrustStore{Entries: map[string]clientcore.TrustStoreEntry{}}
		_, verifyErr := clientcore.VerifyAndPinAnchor(strings.TrimRight(cfg.BaseUrl, "/"), &clientcore.PubkeyResponse{
			UserID: user.ID, EcdhP256: json.RawMessage(user.RequestEncEcdhPubkey), Mlkem768: user.RequestEncMlkemPubkey,
			AnchorEs384PublicKey: user.AnchorEs384PublicKey, AnchorMldsa87PublicKey: user.AnchorMldsa87PublicKey,
			PubkeyBundleSignatureEs384: user.PubkeyBundleSignatureEs384, PubkeyBundleSignatureMldsa87: user.PubkeyBundleSignatureMldsa87, PubkeyBundleVersion: user.PubkeyBundleVersion,
		}, &trust, func(string, string, string) (bool, error) { return true, nil })
		if verifyErr != nil {
			return nil, NewResponseError(http.StatusConflict, "Registered identity cannot be verified")
		}
		return &openBaoEnrollment{Version: 1, UserID: userID, Target: strings.TrimRight(cfg.OpenBaoURL, "/"), Envelope: req.Envelope, RequestKey: user.RequestKey, Trust: trust, UpdatedAt: time.Now().UTC()}, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	err = writeOpenBaoEnrollment(cfg.OpenBaoEnrollmentPath, bundle)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusInternalServerError, "Enrollment could not be saved; approve again to retry"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": true, "enrolled": true, "requestKeyEnabled": true, "target": bundle.Target, "updatedAt": bundle.UpdatedAt})
}

func (e openBaoEnvelope) valid() bool {
	if e.Kind != "revaulter/1" || e.Algorithm != "A256GCM" || e.KeyLabel != "openbao-unseal" {
		return false
	}
	for _, field := range []struct {
		value    string
		min, max int
	}{{e.Value, 1, 4096}, {e.Nonce, 12, 12}, {e.Tag, 16, 16}} {
		decoded, err := base64.RawURLEncoding.DecodeString(field.value)
		if err != nil || len(decoded) < field.min || len(decoded) > field.max || base64.RawURLEncoding.EncodeToString(decoded) != field.value {
			return false
		}
	}
	return true
}

// Reject duplicate keys at every depth before typed decoding rejects unknown fields
func strictEnrollmentJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return errors.New("invalid delimiter")
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, keyErr := d.Token()
				if keyErr != nil {
					return keyErr
				}
				name, valid := key.(string)
				if !valid || keys[name] {
					return errors.New("duplicate key")
				}
				keys[name] = true
			}
			err = walk()
			if err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	err := walk()
	if err != nil {
		return err
	}
	_, err = d.Token()
	if !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func writeOpenBaoEnrollment(path string, bundle *openBaoEnrollment) error {
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".openbao-enrollment-*")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	err = file.Chmod(0o600)
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = file.Close()
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
