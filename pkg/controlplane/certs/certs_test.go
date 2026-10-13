package certs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tykcerts "github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

func TestEncodingSecret(t *testing.T) {
	assert.Equal(t, "private", EncodingSecret("private", "admin"))
	assert.Equal(t, "admin", EncodingSecret("", "admin"))
}

func TestOrgIDFromCertID(t *testing.T) {
	sha := strings.Repeat("a", 64)
	assert.Equal(t, "org1", OrgIDFromCertID("org1"+sha, ""))
	assert.Equal(t, "given", OrgIDFromCertID("org1"+sha, "given"))
	assert.Equal(t, "", OrgIDFromCertID("short", ""))
}

// TestService_RedisRoundTrip adds a certificate through the manager the way
// the Dashboard will, then reads the Redis entries back the way MDCB does
// (tyk-sink/dispatcher/handlers.go GetKeyfunc, cert- branch): decrypt
// cert-raw-<id> with the shared secret and check the org index list.
func TestService_RedisRoundTrip(t *testing.T) {
	conf, err := config.New()
	require.NoError(t, err)
	conf.Storage.Database = 14

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := storage.NewConnectionHandler(ctx)
	go ch.Connect(ctx, nil, conf)
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if !ch.WaitConnect(waitCtx) {
		t.Skip("redis not available")
	}

	const secret = "parity-cert-secret"
	const org = "cporg"
	svc := New(NewManager(ch, secret, false, nil))

	pemData, err := os.ReadFile(filepath.Join("..", "..", "..", "gateway", "testdata", "controlplane", "cert.pem"))
	require.NoError(t, err)

	id, err := svc.Add(pemData, org)
	require.NoError(t, err)
	t.Cleanup(func() { svc.Delete(id, "") })

	// ID is <org><sha256(cert DER)>
	var certBlock *pem.Block
	for rest := pemData; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			certBlock = b
			break
		}
	}
	require.NotNil(t, certBlock)
	sum := sha256.Sum256(certBlock.Bytes)
	assert.Equal(t, org+hex.EncodeToString(sum[:]), id)

	// MDCB read path: raw store, key cert-raw-<id>, decrypt with the secret
	raw := NewStore(ch)
	stored, err := raw.GetKey("raw-" + id)
	require.NoError(t, err)
	assert.Contains(t, stored, "-----BEGIN CERTIFICATE-----")
	assert.NotContains(t, stored, "-----BEGIN PRIVATE KEY-----", "private key must be encrypted at rest")
	blocks, err := tykcerts.ParsePEM([]byte(stored), secret)
	require.NoError(t, err)
	var types []string
	for _, b := range blocks {
		types = append(types, b.Type)
	}
	assert.Contains(t, types, "CERTIFICATE")
	assert.Contains(t, types, "PRIVATE KEY", "ParsePEM with the shared secret yields the decrypted key")

	// org index list used by MDCB's sync worker and by ListAllIds
	index, err := raw.GetListRange(org+"-index", 0, -1)
	require.NoError(t, err)
	assert.Equal(t, []string{"raw-" + id}, index)

	assert.Equal(t, []string{id}, svc.ListIDs(org))
	basics := svc.Basics(org)
	require.Len(t, basics, 1)
	assert.Equal(t, id, basics[0].ID)
	meta, err := svc.Meta(id)
	require.NoError(t, err)
	assert.Equal(t, id, meta.ID)
	_, err = svc.Meta(org + strings.Repeat("0", 64))
	assert.ErrorIs(t, err, ErrNotFound)

	svc.Delete(id, "")
	assert.Empty(t, svc.ListIDs(org))
}
