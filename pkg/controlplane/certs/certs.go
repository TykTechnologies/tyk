// Package certs is the control-plane adapter over tyk/certs: it pins down
// how the certificate manager must be constructed (Redis prefix, encoding
// secret) and carries the request-level logic of the gateway's /tyk/certs
// handler so the gateway and the Dashboard produce identical results.
package certs

import (
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/storage"
)

// KeyPrefix is the Redis prefix of the certificate store. Entries are
// cert-raw-<orgID><sha256> (encrypted PEM) and cert-<orgID>-index (list).
const KeyPrefix = "cert-"

// ErrNotFound is returned when a certificate ID does not resolve.
var ErrNotFound = errors.New("Certificate with given SHA256 fingerprint not found")

// EncodingSecret returns the secret used to encrypt private keys at rest:
// security.private_certificate_encoding_secret when set, else the admin
// secret. Every component sharing the Redis (gateway, MDCB, Dashboard)
// must resolve to the same value.
func EncodingSecret(privateCertificateEncodingSecret, secret string) string {
	if privateCertificateEncodingSecret != "" {
		return privateCertificateEncodingSecret
	}
	return secret
}

// NewStore returns the Redis store the certificate manager must use.
func NewStore(ch *storage.ConnectionHandler) *storage.RedisCluster {
	return &storage.RedisCluster{KeyPrefix: KeyPrefix, HashKeys: false, ConnectionHandler: ch}
}

// NewManager builds a certificate manager over the given connection the
// way the gateway does. cloud disables the index-list migration.
func NewManager(ch *storage.ConnectionHandler, encodingSecret string, cloud bool, log *logrus.Logger, opts ...certs.CertificateManagerOption) certs.CertificateManager {
	store := NewStore(ch)
	store.Connect()
	return certs.NewCertificateManager(store, encodingSecret, log, !cloud, opts...)
}

// Service holds the request-level operations of /tyk/certs.
type Service struct {
	Manager certs.CertificateManager
}

// New returns a Service over an existing manager.
func New(m certs.CertificateManager) *Service {
	return &Service{Manager: m}
}

// Add stores a PEM bundle for orgID and returns the certificate ID
// (<orgID><sha256 hex>).
func (s *Service) Add(pemData []byte, orgID string) (string, error) {
	return s.Manager.Add(pemData, orgID)
}

// ListIDs returns every certificate ID of the org.
func (s *Service) ListIDs(orgID string) []string {
	return s.Manager.ListAllIds(orgID)
}

// Basics returns the summary used by the Dashboard certificate list
// (mode=detailed).
func (s *Service) Basics(orgID string) []*certs.CertificateBasics {
	ids := s.Manager.ListAllIds(orgID)
	out := make([]*certs.CertificateBasics, len(ids))
	for i, c := range s.Manager.List(ids, certs.CertificateAny) {
		out[i] = certs.ExtractCertificateBasics(c, ids[i])
	}
	return out
}

// Meta returns the metadata of one certificate, or ErrNotFound.
func (s *Service) Meta(certID string) (*certs.CertificateMeta, error) {
	c := s.Manager.List([]string{certID}, certs.CertificateAny)
	if len(c) == 0 || c[0] == nil {
		return nil, ErrNotFound
	}
	return certs.ExtractCertificateMeta(c[0], certID), nil
}

// Metas returns the metadata of several certificates; unknown IDs yield a
// nil entry at the same position, as the gateway does.
func (s *Service) Metas(certIDs []string) []*certs.CertificateMeta {
	out := make([]*certs.CertificateMeta, 0, len(certIDs))
	for i, c := range s.Manager.List(certIDs, certs.CertificateAny) {
		if c != nil {
			out = append(out, certs.ExtractCertificateMeta(c, certIDs[i]))
		} else {
			out = append(out, nil)
		}
	}
	return out
}

// Raw returns the stored PEM (certificate chain plus encrypted key).
func (s *Service) Raw(certID string) (string, error) {
	return s.Manager.GetRaw(certID)
}

// Delete removes a certificate. When orgID is empty it is derived from the
// ID prefix, as the gateway handler does.
func (s *Service) Delete(certID, orgID string) {
	s.Manager.Delete(certID, OrgIDFromCertID(certID, orgID))
}

// OrgIDFromCertID returns orgID when set, otherwise the part of certID that
// precedes the 64-character SHA256 fingerprint.
func OrgIDFromCertID(certID, orgID string) string {
	if orgID == "" && len(certID) >= sha256.Size*2 {
		return certID[:len(certID)-sha256.Size*2]
	}
	return orgID
}

// SplitIDs parses the comma-separated ID list accepted by GET /tyk/certs/{ids}.
func SplitIDs(ids string) []string {
	return strings.Split(ids, ",")
}
