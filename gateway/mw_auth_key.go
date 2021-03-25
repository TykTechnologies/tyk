package gateway

import (
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/signature_validator"
)

const (
	defaultSignatureErrorCode    = http.StatusUnauthorized
	defaultSignatureErrorMessage = "Request signature verification failed"
)

const (
	ErrAuthAuthorizationFieldMissing = "auth.auth_field_missing"
	ErrAuthKeyNotFound               = "auth.key_not_found"
)

func init() {
	TykErrors[ErrAuthAuthorizationFieldMissing] = config.TykError{
		Message: "Authorization field missing",
		Code:    http.StatusUnauthorized,
	}

	TykErrors[ErrAuthKeyNotFound] = config.TykError{
		Message: "Access to this API has been disallowed",
		Code:    http.StatusForbidden,
	}
}

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type AuthKey struct {
	BaseMiddleware
}

func (k *AuthKey) Name() string {
	return "AuthKey"
}

func (k *AuthKey) setContextVars(r *http.Request, token string) {
	// Flatten claims and add to context
	if !k.Spec.EnableContextVars {
		return
	}
	if cnt := ctxGetData(r); cnt != nil {
		// Key data
		cnt["token"] = token
		ctxSetData(r, cnt)
	}
}

// getAuthType overrides BaseMiddleware.getAuthType.
func (k *AuthKey) getAuthType() string {
	return authTokenType
}

func (k *AuthKey) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	key, authConfig := k.getAuthToken(k.getAuthType(), r)

	// If key not provided in header or cookie and client certificate is provided, try to find certificate based key
	if authConfig.UseCertificate && key == "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		key = k.Gw.generateToken(k.Spec.OrgID, certs.HexSHA256(r.TLS.PeerCertificates[0].Raw))
	}

	if key == "" {
		// No header value, fail
		k.Logger().Info("Attempted access with malformed header, no auth header found.")

		return errorAndStatusCode(ErrAuthAuthorizationFieldMissing)
	}

	// Ignore Bearer prefix on token if it exists
	key = stripBearer(key)

	// Check if API key valid
	session, keyExists := k.CheckSessionAndIdentityForValidKey(&key, r)
	if !keyExists {
		k.Logger().WithField("key", k.Gw.obfuscateKey(key)).Info("Attempted access with non-existent key.")

		// Fire Authfailed Event
		AuthFailed(k, r, key)

		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "1")

		return errorAndStatusCode(ErrAuthKeyNotFound)
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.AuthToken, apidef.UnsetAuth:
		ctxSetSession(r, &session, key, false, k.Gw.GetConfig().HashKeys)
		k.setContextVars(r, key)
	}

	return k.validateSignature(r, key)
}

func (k *AuthKey) validateSignature(r *http.Request, key string) (error, int) {

	_, authConfig := k.getAuthToken(k.getAuthType(), r)
	logger := k.Logger().WithField("key", k.Gw.obfuscateKey(key))

	if !authConfig.ValidateSignature {
		return nil, http.StatusOK
	}

	errorCode := defaultSignatureErrorCode
	if authConfig.Signature.ErrorCode != 0 {
		errorCode = authConfig.Signature.ErrorCode
	}

	errorMessage := defaultSignatureErrorMessage
	if authConfig.Signature.ErrorMessage != "" {
		errorMessage = authConfig.Signature.ErrorMessage
	}

	validator := signature_validator.SignatureValidator{}
	if err := validator.Init(authConfig.Signature.Algorithm); err != nil {
		logger.WithError(err).Info("Invalid signature verification algorithm")
		return errors.New("internal server error"), http.StatusInternalServerError
	}

	signature := r.Header.Get(authConfig.Signature.Header)
	if signature == "" {
		logger.Info("Request signature header not found or empty")
		return errors.New(errorMessage), errorCode
	}

	secret := k.Gw.replaceTykVariables(r, authConfig.Signature.Secret, false)

	if secret == "" {
		logger.Info("Request signature secret not found or empty")
		return errors.New(errorMessage), errorCode
	}

	if err := validator.Validate(signature, key, secret, authConfig.Signature.AllowedClockSkew); err != nil {
		logger.WithError(err).Info("Request signature validation failed")
		return errors.New(errorMessage), errorCode
	}

	return nil, http.StatusOK
}

func stripBearer(token string) string {
	if len(token) > 6 && strings.ToUpper(token[0:7]) == "BEARER " {
		return token[7:]
	}
	return token
}

func AuthFailed(m TykMiddleware, r *http.Request, token string) {
	m.Base().FireEvent(EventAuthFailure, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "Auth Failure", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           request.RealIP(r),
		Key:              token,
	})
}
