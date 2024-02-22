package gateway

import (
	"net/http"
	"errors"
)

type TokenExchangeMW struct {
	*BaseMiddleware
}
func (k *TokenExchangeMW) Name() string {
	return "TokenExchangeMW"
}

func (k *TokenExchangeMW) EnabledForSpec() bool {
	return k.Spec.TokenExchangeOptions.Enable
}


func (k *TokenExchangeMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	// logger := k.Logger()
	// var tykId string

	// rawJWT, config := k.getAuthToken(k.getAuthType(), r)

	// if rawJWT == "" {
	// 	// No header value, fail
	// 	logger.Info("Attempted access with malformed header, no JWT auth header found.")

	// 	log.Debug("Looked in: ", config.AuthHeaderName)
	// 	log.Debug("Raw data was: ", rawJWT)
	// 	log.Debug("Headers are: ", r.Header)

	// 	k.reportLoginFailure(tykId, r)
	// 	return errors.New("Authorization field missing"), http.StatusBadRequest
	// }

	// // enable bearer token format
	// rawJWT = stripBearer(rawJWT)

	// // Use own validation logic, see below
	// parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	// // Verify the token
	// token, err := parser.Parse(rawJWT, func(token *jwt.Token) (interface{}, error) {
	// 	// Don't forget to validate the alg is what you expect:
	// 	if err := assertSigningMethod(k.Spec.JWTSigningMethod, token); err != nil {
	// 		return nil, err
	// 	}

	// 	val, err := k.getSecretToVerifySignature(r, token)
	// 	if err != nil {
	// 		k.Logger().WithError(err).Error("Couldn't get token")
	// 		return nil, err
	// 	}

	// 	return parseJWTKey(k.Spec.JWTSigningMethod, val)
	// })

	// if err == nil && token.Valid {
	// 	if jwtErr := k.timeValidateJWTClaims(token.Claims.(jwt.MapClaims)); jwtErr != nil {
	// 		return errors.New("Key not authorized: " + jwtErr.Error()), http.StatusUnauthorized
	// 	}

	// 	// Token is valid - let's move on

	// 	// Are we mapping to a central JWT Secret?
	// 	if k.Spec.JWTSource != "" {
	// 		return k.processCentralisedJWT(r, token)
	// 	}

	// 	// No, let's try one-to-one mapping
	// 	return k.processOneToOneTokenMap(r, token)
	// }

	// logger.Info("Attempted JWT access with non-existent key.")
	// k.reportLoginFailure(tykId, r)
	// if err != nil {
	// 	logger.WithError(err).Error("JWT validation error")
	// 	errorDetails := strings.Split(err.Error(), ":")
	// 	if errorDetails[0] == UnexpectedSigningMethod {
	// 		return errors.New(MsgKeyNotAuthorizedUnexpectedSigningMethod), http.StatusForbidden
	// 	}
	// }
	return errors.New("Key not authorized"), http.StatusForbidden
}