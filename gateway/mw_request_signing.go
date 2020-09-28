package gateway

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/v3/certs"
)

type RequestSigning struct {
	BaseMiddleware
}

func (s *RequestSigning) Name() string {
	return "RequestSigning"
}

func (s *RequestSigning) EnabledForSpec() bool {
	return s.Spec.RequestSigning.IsEnabled
}

var supportedAlgorithms = []string{"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512", "rsa-sha256"}

func generateHeaderList(r *http.Request, headerList []string) []string {
	var result []string

	if len(headerList) == 0 {
		result = make([]string, len(r.Header)+1)
		result[0] = "(request-target)"
		i := 1

		for k := range r.Header {
			loweredCaseHeader := strings.ToLower(k)
			result[i] = strings.TrimSpace(loweredCaseHeader)
			i++
		}

		// date header is must as per Signing HTTP Messages Draft
		if r.Header.Get("date") == "" {
			refDate := "Mon, 02 Jan 2006 15:04:05 MST"
			tim := time.Now().Format(refDate)

			r.Header.Set("date", tim)
			result = append(result, "date")
		}
	} else {
		result = make([]string, 0, len(headerList))

		for _, v := range headerList {
			if r.Header.Get(v) != "" {
				result = append(result, v)
			}
		}

		if len(result) == 0 {
			headers := []string{"(request-target)", "date"}
			result = append(result, headers...)

			if r.Header.Get("date") == "" {
				refDate := "Mon, 02 Jan 2006 15:04:05 MST"
				tim := time.Now().Format(refDate)
				r.Header.Set("date", tim)
			}
		}
	}

	return result
}

func (s *RequestSigning) getRequestPath(r *http.Request) string {
	path := r.URL.RequestURI()

	if newURL := ctxGetURLRewriteTarget(r); newURL != nil {
		path = newURL.RequestURI()
	} else {
		if s.Spec.Proxy.StripListenPath {
			path = s.Spec.StripListenPath(r, path)
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
		}
	}

	return path
}

func (s *RequestSigning) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if (s.Spec.RequestSigning.Secret == "" && s.Spec.RequestSigning.CertificateId == "") || s.Spec.RequestSigning.KeyId == "" || s.Spec.RequestSigning.Algorithm == "" {
		log.Error("Fields required for signing the request are missing")
		return errors.New("Fields required for signing the request are missing"), http.StatusInternalServerError
	}

	var algoList []string
	if len(s.Spec.HmacAllowedAlgorithms) > 0 {
		algoList = s.Spec.HmacAllowedAlgorithms
	} else {
		algoList = supportedAlgorithms
	}

	algorithmAllowed := false
	for _, alg := range algoList {
		if alg == s.Spec.RequestSigning.Algorithm {
			algorithmAllowed = true
			break
		}
	}
	if !algorithmAllowed {
		log.WithField("algorithm", s.Spec.RequestSigning.Algorithm).Error("Algorithm not supported")
		return errors.New("Request signing algorithm is not supported"), http.StatusInternalServerError
	}

	headers := generateHeaderList(r, s.Spec.RequestSigning.HeaderList)

	path := s.getRequestPath(r)

	signatureString, err := generateHMACSignatureStringFromRequest(r, headers, path)
	if err != nil {
		log.Error(err)
		return err, http.StatusInternalServerError
	}
	strHeaders := strings.Join(headers, " ")

	var encodedSignature string

	if strings.HasPrefix(s.Spec.RequestSigning.Algorithm, "rsa") {
		if s.Spec.RequestSigning.CertificateId == "" {
			log.Error("CertificateID is empty")
			return errors.New("CertificateID is empty"), http.StatusInternalServerError
		}

		certList := CertificateManager.List([]string{s.Spec.RequestSigning.CertificateId}, certs.CertificatePrivate)
		if len(certList) == 0 || certList[0] == nil {
			log.Error("Certificate not found")
			return errors.New("Certificate not found"), http.StatusInternalServerError
		}
		cert := certList[0]
		rsaKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			log.Error("Certificate does not contain RSA private key")
			return errors.New("Certificate does not contain RSA private key"), http.StatusInternalServerError
		}
		encodedSignature, err = generateRSAEncodedSignature(signatureString, rsaKey, s.Spec.RequestSigning.Algorithm)
		if err != nil {
			log.Error("Error while generating signature:", err)
			return err, http.StatusInternalServerError
		}
	} else {
		var err error
		encodedSignature, err = generateHMACEncodedSignature(signatureString, s.Spec.RequestSigning.Secret, s.Spec.RequestSigning.Algorithm)
		if err != nil {
			return err, http.StatusInternalServerError
		}
	}

	//Generate Authorization header
	authHeader := "Signature "
	//Append keyId
	authHeader += "keyId=\"" + s.Spec.RequestSigning.KeyId + "\","
	//Append algorithm
	authHeader += "algorithm=\"" + s.Spec.RequestSigning.Algorithm + "\","
	//Append Headers
	authHeader += "headers=\"" + strHeaders + "\","
	//Append signature
	authHeader += "signature=\"" + encodedSignature + "\""

	if s.Spec.RequestSigning.SignatureHeader != "" {
		r.Header.Set(s.Spec.RequestSigning.SignatureHeader, authHeader)
		log.Debugf("Setting %s headers as =%s", s.Spec.RequestSigning.SignatureHeader, authHeader)
	} else {
		r.Header.Set("Authorization", authHeader)
		log.Debug("Setting Authorization headers as =", authHeader)
	}

	return nil, http.StatusOK
}

func generateRSAEncodedSignature(signatureString string, privateKey *rsa.PrivateKey, algorithm string) (string, error) {
	var hashFunction hash.Hash
	var hashType crypto.Hash

	switch algorithm {
	case "rsa-sha256":
		hashFunction = sha256.New()
		hashType = crypto.SHA256
	default:
		hashFunction = sha256.New()
		hashType = crypto.SHA256
	}
	hashFunction.Write([]byte(signatureString))
	hashed := hashFunction.Sum(nil)

	rawsignature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hashType, hashed)
	if err != nil {
		return "", err
	}
	encodedSignature := base64.StdEncoding.EncodeToString(rawsignature)

	return encodedSignature, nil
}
