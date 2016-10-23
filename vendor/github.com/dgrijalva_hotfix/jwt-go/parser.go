package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Parser struct {
	ValidMethods  []string // If populated, only these methods will be considered valid
	UseJSONNumber bool     // Use JSON Number format in JSON decoder
}

// Parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func (p *Parser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, NewValidationError("token contains an invalid number of segments", ValidationErrorMalformed)
	}

	var err error
	token := &Token{Raw: tokenString}
	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return token, NewValidationError("tokenstring should not contain 'bearer '", ValidationErrorMalformed)
		}
		return token, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}

	// parse Claims
	var claimBytes []byte
	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	if p.UseJSONNumber {
		dec.UseNumber()
	}
	if err = dec.Decode(&token.Claims); err != nil {
		return token, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}

	// Lookup signature method
	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, NewValidationError("signing method (alg) is unavailable.", ValidationErrorUnverifiable)
		}
	} else {
		return token, NewValidationError("signing method (alg) is unspecified.", ValidationErrorUnverifiable)
	}

	// Verify signing method is in the required set
	if p.ValidMethods != nil {
		var signingMethodValid = false
		var alg = token.Method.Alg()
		for _, m := range p.ValidMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set
			return token, NewValidationError(fmt.Sprintf("signing method %v is invalid", alg), ValidationErrorSignatureInvalid)
		}
	}

	// Lookup key
	var key interface{}
	if keyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, NewValidationError("no Keyfunc was provided.", ValidationErrorUnverifiable)
	}
	if key, err = keyFunc(token); err != nil {
		// keyFunc returned an error
		return token, &ValidationError{Inner: err, Errors: ValidationErrorUnverifiable}
	}

	// Check expiration times
	vErr := &ValidationError{}
	now := TimeFunc().Unix()
	var exp, nbf int64
	var vexp, vnbf bool

	// Parse 'exp' claim
	switch num := token.Claims["exp"].(type) {
	case json.Number:
		if exp, err = num.Int64(); err == nil {
			vexp = true
		}
	case float64:
		vexp = true
		exp = int64(num)
	}

	// Parse 'nbf' claim
	switch num := token.Claims["nbf"].(type) {
	case json.Number:
		if nbf, err = num.Int64(); err == nil {
			vnbf = true
		}
	case float64:
		vnbf = true
		nbf = int64(num)
	}

	if vexp && now > exp {
		delta := time.Unix(now, 0).Sub(time.Unix(exp, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if vnbf && now < nbf {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	// Perform validation
	token.Signature = parts[2]
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		vErr.Inner = err
		vErr.Errors |= ValidationErrorSignatureInvalid
	}

	if vErr.valid() {
		token.Valid = true
		return token, nil
	}

	return token, vErr
}
