package jwkcompat

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Each testdata/v3/<name>.jwks is a JWKS input and <name>.want.json is what
// go-jose v3.0.5 returned for it: either the exact error text, or the parsed
// keys. To add a case, add both files. Run the input through go-jose v3 to
// get the expected result; "note" documents intentional differences.
type wantKey struct {
	KeyID       string `json:"kid"`
	Algorithm   string `json:"alg"`
	Use         string `json:"use"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Certs       int    `json:"certs"`
	CertsURL    string `json:"x5u"`
	X5tSHA1     string `json:"x5t"`
	X5tSHA256   string `json:"x5t#S256"`
}

type want struct {
	Note  string    `json:"note,omitempty"`
	Error string    `json:"error,omitempty"`
	Keys  []wantKey `json:"keys,omitempty"`
}

func fingerprint(key interface{}) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("n=%x e=%d", k.N, k.E)
	case *rsa.PrivateKey:
		return fmt.Sprintf("n=%x e=%d d=%x p=%x q=%x", k.N, k.E, k.D, k.Primes[0], k.Primes[1])
	case *ecdsa.PublicKey:
		return fmt.Sprintf("%s x=%x y=%x", k.Curve.Params().Name, k.X, k.Y)
	case *ecdsa.PrivateKey:
		return fmt.Sprintf("%s x=%x y=%x d=%x", k.Curve.Params().Name, k.X, k.Y, k.D)
	case ed25519.PublicKey:
		return "ed25519 " + hex.EncodeToString(k)
	case ed25519.PrivateKey:
		return "ed25519-private " + hex.EncodeToString(k)
	case []byte:
		return "oct " + hex.EncodeToString(k)
	case nil:
		return "nil"
	}
	return fmt.Sprintf("unknown %T", key)
}

func TestMatchesGoJoseV3(t *testing.T) {
	inputs, err := filepath.Glob("testdata/v3/*.jwks")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) == 0 {
		t.Fatal("no fixtures found in testdata/v3")
	}

	for _, input := range inputs {
		name := strings.TrimSuffix(filepath.Base(input), ".jwks")
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			wantData, err := os.ReadFile(strings.TrimSuffix(input, ".jwks") + ".want.json")
			if err != nil {
				t.Fatal(err)
			}
			var w want
			if err := json.Unmarshal(wantData, &w); err != nil {
				t.Fatal(err)
			}

			set, err := ParseKeySet(data)
			if w.Error != "" {
				if err == nil {
					t.Fatalf("expected error %q, got %d keys", w.Error, len(set.Keys))
				}
				if err.Error() != w.Error {
					t.Fatalf("error text differs from go-jose v3\n got: %s\nwant: %s", err, w.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("go-jose v3 parsed this JWKS, got error: %v", err)
			}

			got := make([]wantKey, 0, len(set.Keys))
			for _, k := range set.Keys {
				gk := wantKey{KeyID: k.KeyID, Algorithm: k.Algorithm, Use: k.Use, Type: fmt.Sprintf("%T", k.Key),
					Fingerprint: fingerprint(k.Key), Certs: len(k.Certificates),
					X5tSHA1: hex.EncodeToString(k.CertificateThumbprintSHA1), X5tSHA256: hex.EncodeToString(k.CertificateThumbprintSHA256)}
				if k.CertificatesURL != nil {
					gk.CertsURL = k.CertificatesURL.String()
				}
				got = append(got, gk)
			}
			if len(got) != len(w.Keys) {
				t.Fatalf("got %d keys, go-jose v3 returned %d", len(got), len(w.Keys))
			}
			for i := range got {
				if got[i] != w.Keys[i] {
					t.Errorf("key %d differs from go-jose v3\n got: %+v\nwant: %+v", i, got[i], w.Keys[i])
				}
			}
		})
	}
}

// The parsed keys must work with the go-jose v4 lookup the Gateway uses.
func TestKeyLookup(t *testing.T) {
	data, err := os.ReadFile("testdata/v3/rsa8192-pub-rsa2048-pub-mixed-set.jwks")
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseKeySet(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, kid := range []string{"big", "small"} {
		keys := set.Key(kid)
		if len(keys) != 1 {
			t.Fatalf("kid %q: got %d keys", kid, len(keys))
		}
		if _, ok := keys[0].Key.(*rsa.PublicKey); !ok {
			t.Fatalf("kid %q: got %T", kid, keys[0].Key)
		}
	}
}

// Primes that cannot form the modulus are rejected before rsa.PrivateKey.Validate,
// which takes cubic time in their size (CVE-2026-116587).
func TestRSAPrivateKeyJunkPrimesRejectedQuickly(t *testing.T) {
	p := make([]byte, 16384/8)
	p[0] = 0x80
	p[len(p)-1] = 1
	n := make([]byte, 2048/8+1)
	n[0] = 1
	jwk := map[string]string{"kty": "RSA", "n": b64(n), "e": "AQAB", "d": "Aw", "p": b64(p), "q": "Aw"}
	data, err := json.Marshal(map[string]interface{}{"keys": []interface{}{jwk}})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = ParseKeySet(data)
	if err == nil || err.Error() != "go-jose/go-jose: invalid RSA private key, p * q != n" {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("rejecting junk primes took %s", elapsed)
	}
}

func TestUnmarshalKey(t *testing.T) {
	var k jose.JSONWebKey
	err := UnmarshalKey([]byte(`{"kty":"oct","k":"AAAA","kid":"s"}`), &k)
	if err != nil {
		t.Fatal(err)
	}
	if k.KeyID != "s" || fingerprint(k.Key) != "oct 000000" {
		t.Fatalf("unexpected key: %+v", k)
	}
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
