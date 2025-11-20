package gateway

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"
	signaturevalidator "github.com/TykTechnologies/tyk/signature_validator"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const (
	defaultSignatureErrorCode    = http.StatusUnauthorized
	defaultSignatureErrorMessage = "Request signature verification failed"
)

const (
	ErrAuthAuthorizationFieldMissing = "auth.auth_field_missing"
	ErrAuthKeyNotFound               = "auth.key_not_found"
	ErrAuthCertNotFound              = "auth.cert_not_found"
	ErrAuthCertExpired               = "auth.cert_expired"
	ErrAuthCertMismatch              = "auth.cert_mismatch"
	ErrAuthKeyIsInvalid              = "auth.key_is_invalid"

	MsgNonExistentKey      = "Attempted access with non-existent key."
	MsgNonExistentCert     = "Attempted access with non-existent cert."
	MsgCertificateMismatch = "Attempted access with incorrect certificate."
	MsgInvalidKey          = "Attempted access with invalid key."
)

func initAuthKeyErrors() {
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

	TykErrors[ErrAuthCertExpired] = config.TykError{
		Message: MsgCertificateExpired,
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrAuthCertMismatch] = config.TykError{
		Message: MsgApiAccessDisallowed,
		Code:    http.StatusForbidden,
	}
}

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type AuthKey struct {
	*BaseMiddleware
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

	// skip auth key check if the request is looped.
	if ses := ctxGetSession(r); ses != nil && httpctx.IsSelfLooping(r) {
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
		certHash = k.Spec.OrgID + crypto.HexSHA256(r.TLS.PeerCertificates[0].Raw)
		if time.Now().After(r.TLS.PeerCertificates[0].NotAfter) {
			return errorAndStatusCode(ErrAuthCertExpired)
		}

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

	// Validate certificate binding or legacy certificate auth
	// Certificate binding validation runs when:
	// 1. Certificate binding is globally enabled AND the session has certificate bindings, OR
	// 2. UseCertificate is explicitly set for this API (legacy dynamic mTLS mode)
	bindingEnabled := k.Gw.GetConfig().Security.EnableCertificateBinding
	hasBindings := len(session.MtlsStaticCertificateBindings) > 0
	if authConfig.UseCertificate || (bindingEnabled && hasBindings) {
		if err, code := k.validateCertificate(r, key, &session, &certHash, &updateSession); err != nil {
			return err, code
		}
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.AuthToken, apidef.UnsetAuth:
		hashKeys := k.Gw.GetConfig().HashKeys
		ctxSetSession(r, &session, updateSession, hashKeys)

		k.setContextVars(r, key)

		attributes := []otel.SpanAttribute{otel.APIKeyAliasAttribute(session.Alias)}

		if hashKeys {
			attributes = append(attributes, otel.APIKeyAttribute(session.KeyHash()))
		}

		ctxSetSpanAttributes(r, k.Name(), attributes...)
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
			return nil, statusCode
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

	validator := signaturevalidator.SignatureValidator{}
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

	secret := k.Gw.ReplaceTykVariables(r, authConfig.Signature.Secret, false)

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

// validateCertificate performs certificate validation for UseCertificate authentication
// It handles both certificate binding mode and legacy auto-update mode
func (k *AuthKey) validateCertificate(r *http.Request, key string, session *user.SessionState, certHash *string, updateSession *bool) (error, int) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return k.validateWithTLSCertificate(r, key, session, certHash, updateSession)
	}
	return k.validateWithoutTLSCertificate(r, key, session)
}

// validateWithTLSCertificate handles validation when a TLS client certificate is provided
func (k *AuthKey) validateWithTLSCertificate(r *http.Request, key string, session *user.SessionState, certHash *string, updateSession *bool) (error, int) {
	// Check certificate expiry when a token is provided (not checked earlier in the flow)
	if err, code := k.checkCertificateExpiry(r, key); err != nil {
		return err, code
	}

	// Compute cert hash for comparison
	*certHash = k.computeCertHash(r, *certHash)

	// Use binding mode only if:
	// 1. Certificate binding is enabled globally, AND
	// 2. The session has static certificate bindings configured
	// Otherwise, use legacy mode for backward compatibility with dynamic mTLS
	bindingEnabled := k.Gw.GetConfig().Security.EnableCertificateBinding
	hasBindings := len(session.MtlsStaticCertificateBindings) > 0
	if bindingEnabled && hasBindings {
		return k.validateCertificateBinding(r, key, session, *certHash)
	}
	return k.validateLegacyMode(r, session, *certHash, updateSession)
}

// validateWithoutTLSCertificate handles validation when no TLS client certificate is provided
func (k *AuthKey) validateWithoutTLSCertificate(r *http.Request, key string, session *user.SessionState) (error, int) {
	// Use binding mode only if:
	// 1. Certificate binding is enabled globally, AND
	// 2. The session has static certificate bindings configured
	// Otherwise, use legacy mode for backward compatibility with dynamic mTLS
	bindingEnabled := k.Gw.GetConfig().Security.EnableCertificateBinding
	hasBindings := len(session.MtlsStaticCertificateBindings) > 0

	if bindingEnabled && hasBindings {
		return k.validateBindingWithoutCert(r, key, session)
	}
	return k.validateLegacyWithoutCert(r, session)
}

// checkCertificateExpiry validates that the certificate hasn't expired
func (k *AuthKey) checkCertificateExpiry(r *http.Request, key string) (error, int) {
	if key != "" && time.Now().After(r.TLS.PeerCertificates[0].NotAfter) {
		return errorAndStatusCode(ErrAuthCertExpired)
	}
	return nil, http.StatusOK
}

// computeCertHash computes the certificate hash if not already computed
func (k *AuthKey) computeCertHash(r *http.Request, existingHash string) string {
	if existingHash == "" {
		return k.Spec.OrgID + crypto.HexSHA256(r.TLS.PeerCertificates[0].Raw)
	}
	return existingHash
}

// validateCertificateBinding validates certificate-to-token binding
// This enforces that the presented certificate matches the one bound to the session
func (k *AuthKey) validateCertificateBinding(r *http.Request, key string, session *user.SessionState, certHash string) (error, int) {
	// Only validate if both token and session have certificate bindings
	if key == "" || len(session.MtlsStaticCertificateBindings) == 0 {
		return nil, http.StatusOK
	}

	// Check if the presented certificate hash matches any of the bound certificates
	certMatched := false
	for _, boundCert := range session.MtlsStaticCertificateBindings {
		if certHash == boundCert {
			certMatched = true
			break
		}
	}

	// If certificates don't match, reject the request
	if !certMatched {
		k.Logger().WithField("key", k.Gw.obfuscateKey(key)).Warn("Certificate mismatch detected for token")
		return k.reportInvalidKey(key, r, MsgCertificateMismatch, ErrAuthCertMismatch)
	}

	// Note: In binding mode, certificate whitelist validation is performed at TLS handshake level (UseMutualTLSAuth)
	// or by CertificateCheckMW middleware. We don't validate against cert manager here because
	// MtlsStaticCertificateBindings contains hashes for binding, not cert IDs for whitelist lookup
	return nil, http.StatusOK
}

// validateLegacyMode handles the legacy auto-update behavior
// Updates session certificate with current cert hash and validates whitelist
func (k *AuthKey) validateLegacyMode(r *http.Request, session *user.SessionState, certHash string, updateSession *bool) (error, int) {
	// Auto-update session certificate with current cert hash
	if session.Certificate != certHash {
		session.Certificate = certHash
		*updateSession = true
	}

	// Validate the certificate exists in cert manager (whitelist check)
	if _, err := k.Gw.CertificateManager.GetRaw(certHash); err != nil {
		return k.reportInvalidKey("", r, MsgNonExistentCert, ErrAuthCertNotFound)
	}

	return nil, http.StatusOK
}

// validateBindingWithoutCert validates when binding is enabled but no certificate is provided
// Rejects only if the session has a certificate bound to it
func (k *AuthKey) validateBindingWithoutCert(r *http.Request, key string, session *user.SessionState) (error, int) {
	if len(session.MtlsStaticCertificateBindings) > 0 {
		k.Logger().WithField("key", k.Gw.obfuscateKey(key)).Warn("Certificate required but not provided")
		return k.reportInvalidKey(key, r, MsgCertificateMismatch, ErrAuthCertMismatch)
	}
	return nil, http.StatusOK
}

// validateLegacyWithoutCert validates session certificate in legacy mode when no TLS cert is provided
// Checks if stored certificate exists in cert manager to catch corrupted data
func (k *AuthKey) validateLegacyWithoutCert(r *http.Request, session *user.SessionState) (error, int) {
	if session.Certificate != "" {
		if _, err := k.Gw.CertificateManager.GetRaw(session.Certificate); err != nil {
			return k.reportInvalidKey("", r, MsgNonExistentCert, ErrAuthCertNotFound)
		}
	}
	return nil, http.StatusOK
}
