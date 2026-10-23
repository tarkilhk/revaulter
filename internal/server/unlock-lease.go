package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/revaulter/internal/db"
)

type unlockLease struct {
	Binding   approvalBinding `json:"binding"`
	ExpiresAt int64           `json:"expiresAt"`
}

type unlockLeaseResponse struct {
	UnlockLeaseID        string `json:"unlockLeaseId,omitempty"`
	UnlockLeaseExpiresAt int64  `json:"unlockLeaseExpiresAt,omitempty"`
}

type approvalGrant struct {
	Binding approvalBinding `json:"binding"`
	LeaseID string          `json:"leaseId,omitempty"`
}

func (s *Server) issueUnlockLease(ctx context.Context, tx *db.DbTx, userID, credentialID, sessionDigest string, verifiedAt time.Time) (*db.AuthChallenge, error) {
	expiry := verifiedAt.Add(approvalTTL).Truncate(time.Second)
	if sessionDigest == "" || !expiry.After(time.Now()) || verifiedAt.After(time.Now()) {
		return nil, approvalDenied()
	}
	binding, err := s.approvalIdentity(ctx, tx, userID, credentialID, "", "")
	if err != nil {
		return nil, err
	}
	return tx.AuthStore().BeginChallenge(ctx, "unlock-lease", userID, sessionDigest, expiry, unlockLease{Binding: binding, ExpiresAt: expiry.Unix()})
}

func (s *Server) validateUnlockLease(c *gin.Context, tx *db.DbTx, userID, leaseID string) (unlockLease, error) {
	var lease unlockLease
	digest := c.GetString(contextKeySessionDigest)
	if digest == "" || userID == "" || leaseID == "" {
		return lease, approvalDenied()
	}
	err := tx.AuthStore().ReadUnlockLease(c.Request.Context(), leaseID, userID, digest, &lease)
	if err != nil || lease.ExpiresAt <= time.Now().Unix() {
		return lease, approvalDenied()
	}
	current, err := s.approvalIdentity(c.Request.Context(), tx, userID, lease.Binding.CredentialID, "", "")
	if err != nil {
		return lease, err
	}
	if current != lease.Binding {
		return lease, approvalDenied()
	}
	return lease, nil
}

func (s *Server) queueAuthChallenge(challenge *db.AuthChallenge) error {
	return s.deleteQueue.Enqueue(deleteEvent{KeyName: "challenge-delete:" + challenge.ID, Kind: "challenge", ID: challenge.ID, TTL: challenge.ExpiresAt.Add(10 * time.Minute)})
}

// Only verified auth handlers call this after cookie issuance and existing rate checks
func (s *Server) sessionUnlockLease(c *gin.Context, sess *authSessionToken, expected *approvalBinding) (unlockLeaseResponse, error) {
	var response unlockLeaseResponse
	if expected == nil || !sess.Ready || sess.VerifiedCredentialID == "" || sess.VerifiedAt <= 0 || time.Unix(sess.VerifiedAt, 0).Add(approvalTTL).Before(time.Now()) {
		return response, nil
	}
	lease, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.AuthChallenge, error) {
		current, err := s.approvalIdentity(ctx, tx, sess.UserID, sess.VerifiedCredentialID, "", "")
		if err != nil {
			return nil, err
		}
		if current != *expected {
			return nil, approvalDenied()
		}
		return s.issueUnlockLease(ctx, tx, sess.UserID, sess.VerifiedCredentialID, c.GetString(contextKeySessionDigest), time.Unix(sess.VerifiedAt, 0))
	})
	if err != nil {
		return response, err
	}
	err = s.queueAuthChallenge(lease)
	if err != nil {
		return response, err
	}
	return unlockLeaseResponse{UnlockLeaseID: lease.ID, UnlockLeaseExpiresAt: lease.ExpiresAt.Unix()}, nil
}

func (s *Server) RouteV2AuthApprovalGrant(c *gin.Context) {
	var req struct {
		LeaseID string `json:"leaseId"`
		State   string `json:"state"`
	}
	err := c.ShouldBindJSON(&req)
	if err != nil || req.State == "" {
		AbortWithErrorJSON(c, approvalDenied())
		return
	}
	userID := c.GetString(contextKeyUserID)
	grant, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.AuthChallenge, error) {
		lease, err := s.validateUnlockLease(c, tx, userID, req.LeaseID)
		if err != nil {
			return nil, err
		}
		binding, err := s.approvalIdentity(ctx, tx, userID, lease.Binding.CredentialID, req.State, "")
		if err != nil {
			return nil, err
		}
		return tx.AuthStore().BeginChallenge(ctx, "approval-grant", userID, req.LeaseID, time.Unix(lease.ExpiresAt, 0), approvalGrant{Binding: binding, LeaseID: req.LeaseID})
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	err = s.queueAuthChallenge(grant)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"grantId": grant.ID})
}
