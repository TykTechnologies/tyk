package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

// Verifies: STK-REQ-023, SYS-REQ-111, SW-REQ-098
// SYS-REQ-111:nominal:nominal
// SW-REQ-098:nominal:nominal
// SW-REQ-098:boundary:nominal
// SW-REQ-098:error_handling:nominal
// SW-REQ-098:error_handling:negative
// SW-REQ-098:security:nominal
// STK-REQ-023:error_handling:negative
// MCDC SYS-REQ-111: certificate_material_operation_requested=F, certificate_material_result_determined=F => TRUE
// MCDC SYS-REQ-111: certificate_material_operation_requested=T, certificate_material_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-111: certificate_material_operation_requested=T, certificate_material_result_determined=F => FALSE -- violation row is the negation of the certificate-material result guarantee; this test asserts requested certificate operations return parsed material, explicit errors, nil missing results, or storage/cache mutations [category: defensive] [reviewed: agent:codex]
func TestCertificateManagerPreservesLifecycleSupportBehavior(t *testing.T) {
	t.Run("constructors preserve defaults and option overrides", func(t *testing.T) {
		manager := NewCertificateManager(storage.NewDummyStorage(), "secret", nil, true)
		require.NotNil(t, manager)
		assert.Equal(t, "secret", manager.secret)
		assert.True(t, manager.migrateCertList)
		assert.Equal(t, DefaultRPCCertFetchMaxElapsedTime, manager.certFetchMaxElapsedTime)
		assert.Equal(t, DefaultRPCCertFetchInitialInterval, manager.certFetchInitialInterval)
		assert.Equal(t, DefaultRPCCertFetchMaxInterval, manager.certFetchMaxInterval)
		assert.True(t, manager.certFetchRetryEnabled)
		assert.Equal(t, DefaultRPCCertFetchMaxRetries, manager.certFetchMaxRetries)

		custom := NewCertificateManager(storage.NewDummyStorage(), "secret", nil, false,
			WithRetryEnabled(false),
			WithMaxRetries(7),
			WithBackoffIntervals(2*time.Second, 20*time.Millisecond, 200*time.Millisecond),
		)
		assert.False(t, custom.certFetchRetryEnabled)
		assert.Equal(t, 7, custom.certFetchMaxRetries)
		assert.Equal(t, 2*time.Second, custom.certFetchMaxElapsedTime)
		assert.Equal(t, 20*time.Millisecond, custom.certFetchInitialInterval)
		assert.Equal(t, 200*time.Millisecond, custom.certFetchMaxInterval)

		slave := NewSlaveCertManager(storage.NewDummyStorage(), storage.NewDummyStorage(), "secret", nil, true, WithRetryEnabled(false))
		require.NotNil(t, slave)
		assert.False(t, slave.certFetchRetryEnabled)
		assert.Equal(t, "secret", slave.secret)
	})

	t.Run("pem parsing and certificate id extraction preserve valid material and reject malformed material", func(t *testing.T) {
		certPEM, keyPEM := genCertificateFromCommonName("reqproof-private", false)
		combinedPEM := append(append([]byte(nil), certPEM...), keyPEM...)

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

		certID, chainPEM, err := GetCertIDAndChainPEM(combinedPEM, "secret")
		require.NoError(t, err)
		require.NotEmpty(t, certID)
		assert.Contains(t, string(chainPEM), "ENCRYPTED PRIVATE KEY")

		blocks, err := ParsePEM(chainPEM, "secret")
		require.NoError(t, err)
		require.Len(t, blocks, 2)
		assert.Equal(t, "CERTIFICATE", blocks[0].Type)
		assert.Equal(t, "PRIVATE KEY", blocks[1].Type)

		cert, err := ParsePEMCertificate(chainPEM, "secret")
		require.NoError(t, err)
		assert.Equal(t, "reqproof-private", cert.Leaf.Subject.CommonName)
		assert.False(t, isPrivateKeyEmpty(cert))
		assert.Equal(t, certID, string(cert.Leaf.Extensions[0].Value))

		publicID, publicChain, err := GetCertIDAndChainPEM(publicPEM, "secret")
		require.NoError(t, err)
		assert.Equal(t, tykcrypto.HexSHA256(publicDER), publicID)
		assert.Equal(t, publicPEM, publicChain)

		publicCert, err := ParsePEMCertificate(publicPEM, "secret")
		require.NoError(t, err)
		assert.True(t, tykcrypto.IsPublicKey(publicCert))

		expiredPEM, _ := genCertificateFromCommonName("expired", true)
		otherCertPEM, otherKeyPEM := genCertificateFromCommonName("other", false)
		badPairPEM := append(append([]byte(nil), otherCertPEM...), keyPEM...)
		twoKeysPEM := append(append([]byte(nil), keyPEM...), otherKeyPEM...)
		mixedPublicAndCert := append(append([]byte(nil), certPEM...), publicPEM...)

		tests := []struct {
			name string
			data []byte
			want string
		}{
			{name: "empty input", data: nil, want: "Failed to decode certificate"},
			{name: "invalid certificate asn1", data: []byte("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"), want: "x509"},
			{name: "expired certificate", data: expiredPEM, want: "certificate is expired"},
			{name: "mismatched private key", data: badPairPEM, want: "private key does not match"},
			{name: "multiple private keys", data: twoKeysPEM, want: "Found multiple private keys"},
			{name: "public key mixed with certificate", data: mixedPublicAndCert, want: "Public keys can't be combined with certificates"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, _, err := GetCertIDAndChainPEM(tt.data, "secret")
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.want)
			})
		}
	})

	t.Run("storage list raw index cache delete and metadata behavior stays deterministic", func(t *testing.T) {
		manager := NewCertificateManager(storage.NewDummyStorage(), "secret", nil, true, WithRetryEnabled(false))
		store := manager.storage.(*storage.DummyStorage)

		publicPEM, _ := genCertificateFromCommonName("public", false)
		privatePEM, privateKeyPEM := genCertificateFromCommonName("private", false)
		privateID, err := manager.Add(append(append([]byte(nil), privatePEM...), privateKeyPEM...), "org-")
		require.NoError(t, err)
		publicID, err := manager.Add(publicPEM, "org-")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(privateID, "org-"))
		assert.Len(t, store.IndexList["org--index"], 2)

		raw, err := manager.GetRaw(privateID)
		require.NoError(t, err)
		assert.Contains(t, raw, "ENCRYPTED PRIVATE KEY")

		_, err = manager.Add(privatePEM, "org-")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")

		dir := t.TempDir()
		filePEM, _ := genCertificateFromCommonName("file", false)
		filePath := filepath.Join(dir, "cert.pem")
		require.NoError(t, os.WriteFile(filePath, filePEM, 0o600))

		listTests := []struct {
			name       string
			ids        []string
			mode       CertificateType
			wantNames  []string
			wantNilPos []int
		}{
			{
				name:       "public mode lists file public and private certificates",
				ids:        []string{filePath, publicID, privateID, "missing"},
				mode:       CertificatePublic,
				wantNames:  []string{"file", "public", "private"},
				wantNilPos: []int{3},
			},
			{
				name:      "private mode filters public-only certificates",
				ids:       []string{publicID, privateID},
				mode:      CertificatePrivate,
				wantNames: []string{"private"},
			},
			{
				name:      "any mode includes public and private certificates",
				ids:       []string{publicID, privateID},
				mode:      CertificateAny,
				wantNames: []string{"public", "private"},
			},
		}

		for _, tt := range listTests {
			t.Run(tt.name, func(t *testing.T) {
				certs := manager.List(tt.ids, tt.mode)
				for _, nilPos := range tt.wantNilPos {
					require.Less(t, nilPos, len(certs))
					assert.Nil(t, certs[nilPos])
				}

				var names []string
				for _, cert := range certs {
					if cert != nil {
						names = append(names, cert.Leaf.Subject.CommonName)
					}
				}
				assert.Equal(t, tt.wantNames, names)
			})
		}

		privateCerts := manager.List([]string{privateID}, CertificatePrivate)
		require.Len(t, privateCerts, 1)
		basics := ExtractCertificateBasics(privateCerts[0], privateID)
		assert.Equal(t, privateID, basics.ID)
		assert.Equal(t, "private", basics.SubjectCN)
		assert.True(t, basics.HasPrivateKey)

		meta := ExtractCertificateMeta(privateCerts[0], privateID)
		assert.Equal(t, privateID, meta.ID)
		assert.Equal(t, "private", meta.Subject.CommonName)
		assert.Equal(t, meta.Subject.CommonName, meta.ToCertificateBasics().SubjectCN)
		assert.Equal(t, privateID[:8]+"***[len="+strconv.Itoa(len(privateID))+"]", MaskCertID(privateID))
		assert.Equal(t, "short", MaskCertID("short"))

		allIDs := manager.ListAllIds("org-")
		assert.ElementsMatch(t, []string{privateID, publicID}, allIDs)

		manager.Delete(privateID, "org-")
		_, err = manager.GetRaw(privateID)
		assert.Error(t, err)
		assert.NotContains(t, manager.ListAllIds("org-"), privateID)

		manager.FlushCache()
		assert.Len(t, manager.List([]string{publicID}, CertificatePublic), 1)
		manager.flushStorage()
		_, err = manager.GetRaw(publicID)
		assert.Error(t, err)
	})

	t.Run("public key helpers and cert pools preserve local selection rules", func(t *testing.T) {
		manager := NewCertificateManager(storage.NewDummyStorage(), "secret", nil, false, WithRetryEnabled(false))

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
		publicID, err := manager.Add(publicPEM, "")
		require.NoError(t, err)

		fingerprints := manager.ListPublicKeys([]string{publicID, "missing"})
		require.Len(t, fingerprints, 2)
		assert.Equal(t, publicID, fingerprints[0])
		assert.Empty(t, fingerprints[1])

		rawKey := manager.ListRawPublicKey(publicID)
		require.NotNil(t, rawKey)
		assert.IsType(t, &rsa.PublicKey{}, rawKey)
		assert.Nil(t, manager.ListRawPublicKey("missing"))

		caPEM, _ := genCertificate(&x509.Certificate{
			Subject:  pkix.Name{CommonName: "ca"},
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign,
		}, false)
		caID, err := manager.Add(caPEM, "")
		require.NoError(t, err)

		pool := manager.CertPool([]string{publicID, caID})
		require.NotNil(t, pool)
		assert.Len(t, pool.Subjects(), 1)
	})

	t.Run("id getter delegates to certificate id extraction", func(t *testing.T) {
		certPEM, _ := genCertificateFromCommonName("id", false)
		getter := NewIdGetter("secret")
		id, err := getter.GetId(certPEM)
		require.NoError(t, err)

		raw, _ := pem.Decode(certPEM)
		assert.Equal(t, tykcrypto.HexSHA256(raw.Bytes), id)
	})
}
