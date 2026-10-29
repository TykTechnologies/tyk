// Package jwkcompat parses JSON Web Key Sets exactly the way go-jose v3 did,
// while returning go-jose v4 types.
//
// Tyk moved from go-jose v3 to v4 to pick up security fixes (CVE-2026-116587,
// CVE-2026-116585, CVE-2026-116586). The v4 JWK parser is stricter than v3: it
// rejects RSA keys larger than 4096 bits, base64url values with "=" padding,
// and some Ed25519 keys. With v4's parser, one such key makes the whole JWKS
// fail to load, so an identity provider that worked before could stop working.
// This package keeps the v3 behaviour for every JWKS.
//
// The parsing logic is ported from go-jose v3.0.5 jwk.go and encoding.go
// (Apache License 2.0, see LICENSE.go-jose) with two deliberate differences,
// both protections against hostile input that still produce an error as before:
//   - an RSA private key whose primes do not multiply to the modulus is rejected
//     before rsa.PrivateKey.Validate is called (the CVE-2026-116587 fix);
//   - JSON nested deeper than 10000 levels is rejected (go-jose v4 JSON decoder).
package jwkcompat

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is a SHA-1 certificate thumbprint (RFC 7517, Section 4.8)
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"
)

// ParseKeySet parses a JSON Web Key Set with go-jose v3 semantics.
func ParseKeySet(data []byte) (*jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if err := UnmarshalKeySet(data, &set); err != nil {
		return nil, err
	}
	return &set, nil
}

// UnmarshalKeySet is the go-jose v3 equivalent of json.Unmarshal(data, set).
// It returns the same keys and the same error text as go-jose v3.
func UnmarshalKeySet(data []byte, set *jose.JSONWebKeySet) error {
	var probe struct {
		Keys []stdjson.RawMessage `json:"keys"`
	}
	if err := stdjson.Unmarshal(data, &probe); err != nil {
		// Invalid JSON or a wrong top-level shape: let encoding/json report it
		// against the go-jose types, so the error reads the same as with v3.
		return stdjson.Unmarshal(data, set)
	}

	var compat struct {
		Keys []compatKey `json:"keys"`
	}
	err := stdjson.Unmarshal(data, &compat)
	if compat.Keys != nil {
		set.Keys = make([]jose.JSONWebKey, len(compat.Keys))
		for i := range compat.Keys {
			set.Keys[i] = compat.Keys[i].JSONWebKey
		}
	} else if probe.Keys == nil {
		set.Keys = nil
	}
	return err
}

// UnmarshalKey is the go-jose v3 equivalent of key.UnmarshalJSON(data).
func UnmarshalKey(data []byte, k *jose.JSONWebKey) error {
	return unmarshalKey(data, k)
}

type compatKey struct {
	jose.JSONWebKey
}

func (k *compatKey) UnmarshalJSON(data []byte) error {
	return unmarshalKey(data, &k.JSONWebKey)
}

// rawJSONWebKey represents a public or private key in JWK format, used for
// parsing/serializing.
type rawJSONWebKey struct {
	Use string      `json:"use,omitempty"`
	Kty string      `json:"kty,omitempty"`
	Kid string      `json:"kid,omitempty"`
	Crv string      `json:"crv,omitempty"`
	Alg string      `json:"alg,omitempty"`
	K   *byteBuffer `json:"k,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
	N   *byteBuffer `json:"n,omitempty"`
	E   *byteBuffer `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  *byteBuffer `json:"d,omitempty"`
	P  *byteBuffer `json:"p,omitempty"`
	Q  *byteBuffer `json:"q,omitempty"`
	Dp *byteBuffer `json:"dp,omitempty"`
	Dq *byteBuffer `json:"dq,omitempty"`
	Qi *byteBuffer `json:"qi,omitempty"`
	// Certificates
	X5c       []string `json:"x5c,omitempty"`
	X5u       string   `json:"x5u,omitempty"`
	X5tSHA1   string   `json:"x5t,omitempty"`
	X5tSHA256 string   `json:"x5t#S256,omitempty"`
}

// rawKeyType is renamed to "jose.rawJSONWebKey" in decode errors, as go-jose v3 named it.
var rawKeyType = reflect.TypeOf(rawJSONWebKey{})

func unmarshalKey(data []byte, k *jose.JSONWebKey) (err error) {
	var raw rawJSONWebKey
	err = json.Unmarshal(data, &raw)
	if err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Type == rawKeyType {
			return errors.New(strings.Replace(err.Error(), rawKeyType.String(), "jose.rawJSONWebKey", 1))
		}
		return err
	}

	certs, err := parseCertificateChain(raw.X5c)
	if err != nil {
		return fmt.Errorf("go-jose/go-jose: failed to unmarshal x5c field: %w", err)
	}

	var key interface{}
	var certPub interface{}
	var keyPub interface{}

	if len(certs) > 0 {
		// We need to check that leaf public key matches the key embedded in this
		// JWK, as required by the standard (see RFC 7517, Section 4.7). Otherwise
		// the JWK parsed could be semantically invalid. Technically, should also
		// check key usage fields and other extensions on the cert here, but the
		// standard doesn't exactly explain how they're supposed to map from the
		// JWK representation to the X.509 extensions.
		certPub = certs[0].PublicKey
	}

	switch raw.Kty {
	case "EC":
		if raw.D != nil {
			var priv *ecdsa.PrivateKey
			priv, err = raw.ecPrivateKey()
			if err == nil {
				key, keyPub = priv, priv.Public()
			}
		} else {
			key, err = raw.ecPublicKey()
			keyPub = key
		}
	case "RSA":
		if raw.D != nil {
			var priv *rsa.PrivateKey
			priv, err = raw.rsaPrivateKey()
			if err == nil {
				key, keyPub = priv, priv.Public()
			}
		} else {
			key, err = raw.rsaPublicKey()
			keyPub = key
		}
	case "oct":
		if certPub != nil {
			return errors.New("go-jose/go-jose: invalid JWK, found 'oct' (symmetric) key with cert chain")
		}
		key, err = raw.symmetricKey()
	case "OKP":
		if raw.Crv == "Ed25519" && raw.X != nil {
			if raw.D != nil {
				var priv ed25519.PrivateKey
				priv, err = raw.edPrivateKey()
				if err == nil {
					key, keyPub = priv, priv.Public()
				}
			} else {
				key, err = raw.edPublicKey()
				keyPub = key
			}
		} else {
			err = fmt.Errorf("go-jose/go-jose: unknown curve %s'", raw.Crv)
		}
	default:
		err = fmt.Errorf("go-jose/go-jose: unknown json web key type '%s'", raw.Kty)
	}

	if err != nil {
		return
	}

	if certPub != nil && keyPub != nil {
		if !reflect.DeepEqual(certPub, keyPub) {
			return errors.New("go-jose/go-jose: invalid JWK, public keys in key and x5c fields do not match")
		}
	}

	*k = jose.JSONWebKey{Key: key, KeyID: raw.Kid, Algorithm: raw.Alg, Use: raw.Use, Certificates: certs}

	if raw.X5u != "" {
		k.CertificatesURL, err = url.Parse(raw.X5u)
		if err != nil {
			return fmt.Errorf("go-jose/go-jose: invalid JWK, x5u header is invalid URL: %w", err)
		}
	}

	// x5t parameters are base64url-encoded SHA thumbprints
	// See RFC 7517, Section 4.8, https://tools.ietf.org/html/rfc7517#section-4.8
	x5tSHA1bytes, err := base64URLDecode(raw.X5tSHA1)
	if err != nil {
		return errors.New("go-jose/go-jose: invalid JWK, x5t header has invalid encoding")
	}

	// RFC 7517, Section 4.8 is ambiguous as to whether the digest output should be byte or hex,
	// for this reason, after base64 decoding, if the size is sha1.Size it's likely that the value is a byte encoded
	// checksum so we skip this. Otherwise if the checksum was hex encoded we expect a 40 byte sized array so we'll
	// try to hex decode it. When Marshalling this value we'll always use a base64 encoded version of byte format checksum.
	if len(x5tSHA1bytes) == 2*sha1.Size {
		hx, err := hex.DecodeString(string(x5tSHA1bytes))
		if err != nil {
			return fmt.Errorf("go-jose/go-jose: invalid JWK, unable to hex decode x5t: %w", err)

		}
		x5tSHA1bytes = hx
	}

	k.CertificateThumbprintSHA1 = x5tSHA1bytes

	x5tSHA256bytes, err := base64URLDecode(raw.X5tSHA256)
	if err != nil {
		return errors.New("go-jose/go-jose: invalid JWK, x5t#S256 header has invalid encoding")
	}

	if len(x5tSHA256bytes) == 2*sha256.Size {
		hx256, err := hex.DecodeString(string(x5tSHA256bytes))
		if err != nil {
			return fmt.Errorf("go-jose/go-jose: invalid JWK, unable to hex decode x5t#S256: %w", err)
		}
		x5tSHA256bytes = hx256
	}

	k.CertificateThumbprintSHA256 = x5tSHA256bytes

	x5tSHA1Len := len(k.CertificateThumbprintSHA1)
	x5tSHA256Len := len(k.CertificateThumbprintSHA256)
	if x5tSHA1Len > 0 && x5tSHA1Len != sha1.Size {
		return errors.New("go-jose/go-jose: invalid JWK, x5t header is of incorrect size")
	}
	if x5tSHA256Len > 0 && x5tSHA256Len != sha256.Size {
		return errors.New("go-jose/go-jose: invalid JWK, x5t#S256 header is of incorrect size")
	}

	// If certificate chain *and* thumbprints are set, verify correctness.
	if len(k.Certificates) > 0 {
		leaf := k.Certificates[0]
		sha1sum := sha1.Sum(leaf.Raw) //nolint:gosec // x5t is a SHA-1 certificate thumbprint (RFC 7517, Section 4.8)
		sha256sum := sha256.Sum256(leaf.Raw)

		if len(k.CertificateThumbprintSHA1) > 0 && !bytes.Equal(sha1sum[:], k.CertificateThumbprintSHA1) {
			return errors.New("go-jose/go-jose: invalid JWK, x5c thumbprint does not match x5t value")
		}

		if len(k.CertificateThumbprintSHA256) > 0 && !bytes.Equal(sha256sum[:], k.CertificateThumbprintSHA256) {
			return errors.New("go-jose/go-jose: invalid JWK, x5c thumbprint does not match x5t#S256 value")
		}
	}

	return
}

func parseCertificateChain(chain []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, len(chain))
	for i, cert := range chain {
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, err
		}
		out[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (key rawJSONWebKey) ecPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("go-jose/go-jose: unsupported elliptic curve '%s'", key.Crv)
	}

	if key.X == nil || key.Y == nil {
		return nil, errors.New("go-jose/go-jose: invalid EC key, missing x/y values")
	}

	// The length of this octet string MUST be the full size of a coordinate for
	// the curve specified in the "crv" parameter.
	// https://tools.ietf.org/html/rfc7518#section-6.2.1.2
	if curveSize(curve) != len(key.X.data) {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC public key, wrong length for x")
	}

	if curveSize(curve) != len(key.Y.data) {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC public key, wrong length for y")
	}

	x := key.X.bigInt()
	y := key.Y.bigInt()

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("go-jose/go-jose: invalid EC key, X/Y are not on declared curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (key rawJSONWebKey) ecPrivateKey() (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("go-jose/go-jose: unsupported elliptic curve '%s'", key.Crv)
	}

	if key.X == nil || key.Y == nil || key.D == nil {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC private key, missing x/y/d values")
	}

	// The length of this octet string MUST be the full size of a coordinate for
	// the curve specified in the "crv" parameter.
	// https://tools.ietf.org/html/rfc7518#section-6.2.1.2
	if curveSize(curve) != len(key.X.data) {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC private key, wrong length for x")
	}

	if curveSize(curve) != len(key.Y.data) {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC private key, wrong length for y")
	}

	// https://tools.ietf.org/html/rfc7518#section-6.2.2.1
	if dSize(curve) != len(key.D.data) {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC private key, wrong length for d")
	}

	x := key.X.bigInt()
	y := key.Y.bigInt()

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("go-jose/go-jose: invalid EC key, X/Y are not on declared curve")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: key.D.bigInt(),
	}, nil
}

func (key rawJSONWebKey) rsaPublicKey() (*rsa.PublicKey, error) {
	if key.N == nil || key.E == nil {
		return nil, fmt.Errorf("go-jose/go-jose: invalid RSA key, missing n/e values")
	}

	return &rsa.PublicKey{
		N: key.N.bigInt(),
		E: key.E.toInt(),
	}, nil
}

func (key rawJSONWebKey) rsaPrivateKey() (*rsa.PrivateKey, error) {
	var missing []string
	switch {
	case key.N == nil:
		missing = append(missing, "N")
	case key.E == nil:
		missing = append(missing, "E")
	case key.D == nil:
		missing = append(missing, "D")
	case key.P == nil:
		missing = append(missing, "P")
	case key.Q == nil:
		missing = append(missing, "Q")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("go-jose/go-jose: invalid RSA private key, missing %s value(s)", strings.Join(missing, ", "))
	}

	n, p, q := key.N.bigInt(), key.P.bigInt(), key.Q.bigInt()

	// Not in go-jose v3: rsa.PrivateKey.Validate takes cubic time in the size of
	// the primes (CVE-2026-116587), so reject primes that cannot form the
	// modulus first. Validate rejects such keys too, so the outcome is unchanged.
	if p.BitLen()+q.BitLen() > n.BitLen()+1 || new(big.Int).Mul(p, q).Cmp(n) != 0 {
		return nil, errors.New("go-jose/go-jose: invalid RSA private key, p * q != n")
	}

	rv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: key.E.toInt(),
		},
		D: key.D.bigInt(),
		Primes: []*big.Int{
			p,
			q,
		},
	}

	if key.Dp != nil {
		rv.Precomputed.Dp = key.Dp.bigInt()
	}
	if key.Dq != nil {
		rv.Precomputed.Dq = key.Dq.bigInt()
	}
	if key.Qi != nil {
		rv.Precomputed.Qinv = key.Qi.bigInt()
	}

	err := rv.Validate()
	return rv, err
}

func (key rawJSONWebKey) edPrivateKey() (ed25519.PrivateKey, error) {
	var missing []string
	switch {
	case key.D == nil:
		missing = append(missing, "D")
	case key.X == nil:
		missing = append(missing, "X")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("go-jose/go-jose: invalid Ed25519 private key, missing %s value(s)", strings.Join(missing, ", "))
	}

	privateKey := make([]byte, ed25519.PrivateKeySize)
	copy(privateKey[0:32], key.D.bytes())
	copy(privateKey[32:], key.X.bytes())
	rv := ed25519.PrivateKey(privateKey)
	return rv, nil
}

func (key rawJSONWebKey) edPublicKey() (ed25519.PublicKey, error) {
	if key.X == nil {
		return nil, fmt.Errorf("go-jose/go-jose: invalid Ed key, missing x value")
	}
	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey[0:32], key.X.bytes())
	rv := ed25519.PublicKey(publicKey)
	return rv, nil
}

func (key rawJSONWebKey) symmetricKey() ([]byte, error) {
	if key.K == nil {
		return nil, fmt.Errorf("go-jose/go-jose: invalid OCT (symmetric) key, missing k value")
	}
	return key.K.bytes(), nil
}

// Get size of curve in bytes
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / 8
	mod := bits % 8

	if mod == 0 {
		return div
	}

	return div + 1
}

func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / 8
	if bitLen%8 != 0 {
		size++
	}
	return size
}

// byteBuffer represents a slice of bytes that can be serialized to url-safe base64.
type byteBuffer struct {
	data []byte
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: data,
	}
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64URLDecode(encoded)
	if err != nil {
		return err
	}

	*b = *newBuffer(decoded)

	return nil
}

func (b *byteBuffer) bytes() []byte {
	// Handling nil here allows us to transparently handle nil slices when serializing.
	if b == nil {
		return nil
	}
	return b.data
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func (b byteBuffer) toInt() int {
	return int(b.bigInt().Int64())
}

// base64URLDecode is implemented as defined in https://www.rfc-editor.org/rfc/rfc7515.html#appendix-C
func base64URLDecode(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")
	return base64.RawURLEncoding.DecodeString(value)
}
