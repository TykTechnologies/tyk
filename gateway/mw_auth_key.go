package gateway

import (
	"errors"
	"net/http"
	"slices"
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
	ErrAuthKeyIsInvalid              = "auth.key_is_invalid"
	ErrAuthCertRequired              = "auth.cert_required"
	ErrAuthCertMismatch              = "auth.cert_mismatch"

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

	TykErrors[ErrAuthCertRequired] = config.TykError{
		Message: MsgAuthCertRequired,
		Code:    http.StatusUnauthorized,
	}

	TykErrors[ErrAuthCertMismatch] = config.TykError{
		Message: MsgApiAccessDisallowed,
		Code:    http.StatusUnauthorized,
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
	if key == "" {
		key = stripBearer(key)
	}
	var keyExists, updateSession bool
	var certHash string
	var session user.SessionState
	if authConfig.UseCertificate && r.TLS != nil {
		if len(r.TLS.PeerCertificates) > 0 {
			if time.Now().After(r.TLS.PeerCertificates[0].NotAfter) {
				return errorAndStatusCode(ErrAuthCertExpired)
			}
			certHash = k.Spec.OrgID + crypto.HexSHA256(r.TLS.PeerCertificates[0].Raw)
		}

		if !k.Gw.GetConfig().Security.AllowUnsafeDynamicMTLSToken {
			if certHash == "" {
				return errorAndStatusCode(ErrAuthCertRequired)
			}
			key = k.Gw.generateToken(k.Spec.OrgID, certHash)
			session, keyExists = k.CheckSessionAndIdentityForValidKey(key, r)
			if !keyExists {
				return errorAndStatusCode(ErrAuthCertMismatch)
			}
		} else {
			if key != "" {
				session, keyExists = k.CheckSessionAndIdentityForValidKey(key, r)
				key = session.KeyID
				if !keyExists {
					session, keyExists = k.CheckSessionAndIdentityForValidKey(certHash, r)
					if !keyExists {
						return k.reportInvalidKey(key, r, MsgNonExistentKey, ErrAuthKeyNotFound)
					}
				}
			}
		}
	}

	// Validate certificate binding or dynamic mTLS
	// Certificate binding validation runs when:
	// 1. The session has certificate bindings AND static mTLS is enabled (certificate-token binding), OR
	// 2. UseCertificate is explicitly set for this API (dynamic mTLS mode)
	useCertBinding := k.shouldValidateCertificateBinding(&session)
	if authConfig.UseCertificate || useCertBinding {
		ctx := &certValidationContext{
			request:        r,
			key:            key,
			session:        &session,
			certHash:       &certHash,
			updateSession:  &updateSession,
			useCertBinding: useCertBinding,
		}
		if code, err := k.validateCertificate(ctx); err != nil {
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

// certValidationContext holds all the context needed for certificate validation
type certValidationContext struct {
	request        *http.Request
	key            string
	session        *user.SessionState
	certHash       *string
	updateSession  *bool
	useCertBinding bool
}

// shouldValidateCertificateBinding determines if certificate-token binding should be enforced.
// Certificate binding only applies when static mTLS is enabled at the API level.
func (k *AuthKey) shouldValidateCertificateBinding(session *user.SessionState) bool {
	return len(session.MtlsStaticCertificateBindings) > 0 && k.Spec.UseMutualTLSAuth
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

// validateCertificate performs certificate validation for both certificate binding and dynamic mTLS
func (k *AuthKey) validateCertificate(ctx *certValidationContext) (int, error) {
	if ctx.request.TLS != nil && len(ctx.request.TLS.PeerCertificates) > 0 {
		return k.validateWithTLSCertificate(ctx)
	}

	// Certificate binding validation is not needed here because CertificateCheckMW
	// rejects requests without certificates before reaching this code when UseMutualTLSAuth=true
	return k.validateLegacyWithoutCert(ctx.request, ctx.session)
}

// validateWithTLSCertificate handles validation when a TLS client certificate is provided
func (k *AuthKey) validateWithTLSCertificate(ctx *certValidationContext) (int, error) {
	// Check certificate expiry when a token is provided (not checked earlier in the flow)
	if code, err := k.checkCertificateExpiry(ctx.request, ctx.key); err != nil {
		return code, err
	}

	// Compute cert hash for comparison
	*ctx.certHash = k.computeCertHash(ctx.request, *ctx.certHash)

	// Use binding mode if the session has static certificate bindings configured
	// Otherwise, use legacy mode for backward compatibility with dynamic mTLS
	if ctx.useCertBinding {
		return k.validateCertificateBinding(ctx.request, ctx.key, ctx.session, *ctx.certHash)
	}

	return k.validateLegacyMode(ctx.request, ctx.session, *ctx.certHash, ctx.updateSession)
}

// checkCertificateExpiry validates that the certificate hasn't expired
func (k *AuthKey) checkCertificateExpiry(r *http.Request, key string) (int, error) {
	if key != "" && time.Now().After(r.TLS.PeerCertificates[0].NotAfter) {
		err, code := errorAndStatusCode(ErrAuthCertExpired)
		return code, err
	}

	return http.StatusOK, nil
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
func (k *AuthKey) validateCertificateBinding(r *http.Request, key string, session *user.SessionState, certHash string) (int, error) {
	// Only validate if both token and session have certificate bindings
	if key == "" || len(session.MtlsStaticCertificateBindings) == 0 {
		return http.StatusOK, nil
	}

	// Check if the presented certificate hash matches any of the bound certificates
	certMatched := slices.Contains(session.MtlsStaticCertificateBindings, certHash)

	// If certificates don't match, reject the request
	if !certMatched {
		k.Logger().WithField("key", k.Gw.obfuscateKey(key)).Warn("Certificate mismatch detected for token")
		err, code := k.reportInvalidKey(key, r, MsgCertificateMismatch, ErrAuthCertMismatch)
		return code, err
	}

	// Note: In binding mode, certificate whitelist validation is performed at TLS handshake level (UseMutualTLSAuth)
	// or by CertificateCheckMW middleware. We don't validate against cert manager here because
	// MtlsStaticCertificateBindings contains hashes for binding, not cert IDs for whitelist lookup
	return http.StatusOK, nil
}

// validateLegacyMode handles the dynamic mtls behavior
func (k *AuthKey) validateLegacyMode(r *http.Request, session *user.SessionState, certHash string, updateSession *bool) (int, error) {
	// Auto-update session certificate with current cert hash
	if session.Certificate != certHash {
		session.Certificate = certHash
		*updateSession = true
	}

	// Validate the certificate exists in cert manager
	if _, err := k.Gw.CertificateManager.GetRaw(certHash); err != nil {
		err, code := k.reportInvalidKey("", r, MsgNonExistentCert, ErrAuthCertNotFound)
		return code, err
	}

	return http.StatusOK, nil
}

// validateLegacyWithoutCert validates session certificate in dynamic mTLS mode when no TLS cert is provided
// Checks if stored certificate exists in cert manager to catch corrupted data
func (k *AuthKey) validateLegacyWithoutCert(r *http.Request, session *user.SessionState) (int, error) {
	if session.Certificate != "" {
		if _, err := k.Gw.CertificateManager.GetRaw(session.Certificate); err != nil {
			err, code := k.reportInvalidKey("", r, MsgNonExistentCert, ErrAuthCertNotFound)
			return code, err
		}
	}

	return http.StatusOK, nil
}
