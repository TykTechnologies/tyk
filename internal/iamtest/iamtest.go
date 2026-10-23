// Package iamtest provides hermetic test helpers for exercising the GCP IAM
// credentials provider offline. It stands up a local OAuth2 token server and a
// per-run fake service-account key so tests can drive the provider's success
// path — including the eager token mint in storage v1.4.1+ — without contacting
// Google.
package iamtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// FakeADC points GOOGLE_APPLICATION_CREDENTIALS at a per-run service-account key
// whose token_uri targets a local token server that returns a static access
// token. This lets iamauth.NewProvider(gcp) resolve credentials and mint its
// initial token entirely offline. The server and env var are torn down when the
// test ends.
func FakeADC(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if _, err := w.Write([]byte(`{"access_token":"fake-token","token_type":"Bearer","expires_in":3600}`)); err != nil {
			t.Errorf("writing token response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	sa := map[string]string{
		"type":         "service_account",
		"project_id":   "test-project",
		"private_key":  string(pemKey),
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"client_id":    "1234567890",
		"token_uri":    srv.URL,
	}

	data, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshaling service account: %v", err)
	}

	path := filepath.Join(t.TempDir(), "fake-adc.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing adc file: %v", err)
	}

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}
