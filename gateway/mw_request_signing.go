package gateway

import (
	"errors"
	"net/http"
	"strings"
	"time"
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

var supportedAlgorithms = []string{"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"}

func generateHeaderList(r *http.Request) []string {
	headers := make([]string, len(r.Header)+1)

	headers[0] = "(request-target)"
	i := 1

	for k := range r.Header {
		loweredCaseHeader := strings.ToLower(k)
		headers[i] = strings.TrimSpace(loweredCaseHeader)
		i++
	}

	//Date header is must as per Signing HTTP Messages Draft
	if r.Header.Get("date") == "" {
		refDate := "Mon, 02 Jan 2006 15:04:05 MST"
		tim := time.Now().Format(refDate)

		r.Header.Set("date", tim)
		headers = append(headers, "date")
	}

	return headers
}

func (s *RequestSigning) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if s.Spec.RequestSigning.Secret == "" || s.Spec.RequestSigning.KeyId == "" || s.Spec.RequestSigning.Algorithm == "" {
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
		return errors.New("Request signing Algorithm is not supported"), http.StatusInternalServerError
	}

	headers := generateHeaderList(r)
	signatureString, err := generateHMACSignatureStringFromRequest(r, headers)
	if err != nil {
		log.Error(err)
		return err, http.StatusInternalServerError
	}

	strHeaders := strings.Join(headers, " ")
	encodedSignature := generateEncodedSignature(signatureString, s.Spec.RequestSigning.Secret, s.Spec.RequestSigning.Algorithm)

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

	r.Header.Set("Authorization", authHeader)
	log.Debug("Setting Authorization headers as =", authHeader)

	return nil, http.StatusOK
}
