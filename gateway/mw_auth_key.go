package gateway

import (
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/apidef"
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
	ErrAuthCertNotFound              = "auth.cert_not_found"
	ErrAuthKeyIsInvalid              = "auth.key_is_invalid"

	MsgNonExistentKey  = "Attempted access with non-existent key."
	MsgNonExistentCert = "Attempted access with non-existent cert."
	MsgInvalidKey      = "Attempted access with invalid key."
)

func init() {
	TykErrors[ErrAuthAuthorizationFieldMissing] = config.TykError{
		Message: MsgAuthFieldMissing,
		Code:    http.StatusUnauthorized,
	}

	TykErrors[ErrAuthKeyNotFound] = config.TykError{
		Message: MsgApiAccessDisallowed,
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrAuthCertNotFound] = config.TykError{
		Message: MsgApiAccessDisallowed,
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrAuthKeyIsInvalid] = config.TykError{
		Message: MsgApiAccessDisallowed,
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
	return apidef.AuthTokenType
}

func (k *AuthKey) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	key, authConfig := k.getAuthToken(k.getAuthType(), r)
	var certHash string

	keyExists := false
	var session user.SessionState
	updateSession := false
	if key != "" {
		key = stripBearer(key)
	} else if authConfig.UseCertificate && key == "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		log.Debug("Trying to find key by client certificate")
		certHash = k.Spec.OrgID + certs.HexSHA256(r.TLS.PeerCertificates[0].Raw)
		key = k.Gw.generateToken(k.Spec.OrgID, certHash)
	} else {
		k.Logger().Info("Attempted access with malformed header, no auth header found.")
		return errorAndStatusCode(ErrAuthAuthorizationFieldMissing)
	}

	session, keyExists = k.CheckSessionAndIdentityForValidKey(key, r)
	key = session.KeyID
	if !keyExists {
		// fallback to search by cert
		session, keyExists = k.CheckSessionAndIdentityForValidKey(certHash, r)
		if !keyExists {
			return k.reportInvalidKey(key, r, MsgNonExistentKey, ErrAuthKeyNotFound)
		}
	}

	if authConfig.UseCertificate {
		certLookup := session.Certificate

		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certLookup = certHash
			if session.Certificate != certHash {
				session.Certificate = certHash
				updateSession = true
			}
		}

		if _, err := k.Gw.CertificateManager.GetRaw(certLookup); err != nil {
			return k.reportInvalidKey(key, r, MsgNonExistentCert, ErrAuthCertNotFound)
		}
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.AuthToken, apidef.UnsetAuth:
		ctxSetSession(r, &session, updateSession, k.Gw.GetConfig().HashKeys)
		k.setContextVars(r, key)
	}

	// Try using org-key format first:
	if strings.HasPrefix(key, session.OrgID) {
		err, statusCode := k.validateSignature(r, key[len(session.OrgID):])
		if err == nil && statusCode == http.StatusOK {
			return err, statusCode
		}
	}

	// As a second approach, try to use the internal ID that's part of the B64 JSON key:
	keyID, err := storage.TokenID(key)
	if err == nil {
		err, statusCode := k.validateSignature(r, keyID)
		if err == nil {
			return err, statusCode
		}
	}

	// Last try is to take the key as is:
	return k.validateSignature(r, key)
}

func (k *AuthKey) reportInvalidKey(key string, r *http.Request, msg string, errMsg string) (error, int) {
	k.Logger().WithField("key", k.Gw.obfuscateKey(key)).Info(msg)

	// Fire Authfailed Event
	AuthFailed(k, r, key)

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "1")

	return errorAndStatusCode(errMsg)
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

	paramName := authConfig.Signature.ParamName
	if authConfig.Signature.UseParam || paramName != "" {
		if paramName == "" {
			paramName = authConfig.Signature.Header
		}

		paramValue := r.URL.Query().Get(paramName)

		// Only use the paramValue if it has an actual value
		if paramValue != "" {
			signature = paramValue
		}
	}

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

// TODO: move this method to base middleware?
func AuthFailed(m TykMiddleware, r *http.Request, token string) {
	m.Base().FireEvent(EventAuthFailure, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "Auth Failure", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           request.RealIP(r),
		Key:              token,
	})
}
