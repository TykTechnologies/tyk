// Tyk Gateway API
// ErrRequestMalformed indicates an error when the request body cannot be parsed.
var ErrRequestMalformed = errors.New("request malformed")

// VersionMetas holds version metadata for multiple APIs.
type VersionMetas struct {
	Status string        `json:"status"`
	Metas  []VersionMeta `json:"apis"`
}

// VersionMeta holds individual version metadata for an API.
type VersionMeta struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	VersionName      string `json:"versionName"`
	Internal         bool   `json:"internal"`
	ExpirationDate   string `json:"expirationDate"`
	IsDefaultVersion bool   `json:"isDefaultVersion"`
}

// MethodNotAllowedHandler is a handler for HTTP requests with methods that are not allowed.
type MethodNotAllowedHandler struct{}

// PolicyUpdateObj represents an object for updating API access policies.
type PolicyUpdateObj struct {
	Policy        string   `json:"policy"`
	ApplyPolicies []string `json:"apply_policies"`
}

// RevokeTokenHandler handles the revocation of a specific token.
func (gw *Gateway) RevokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Implementation omitted for brevity
}

// GetStorageForApi returns the storage interface for a specified API ID.
func (gw *Gateway) GetStorageForApi(apiID string) (ExtendedOsinStorageInterface, int, error) {
	// Implementation omitted for brevity
}

// RevokeAllTokensHandler handles the revocation of all tokens associated with a specific client.
func (gw *Gateway) RevokeAllTokensHandler(w http.ResponseWriter, r *http.Request) {
	// Implementation omitted for brevity
}
}

		return
	}

	if clientSecret == "" {
		doJSONWrite(w, http.StatusUnauthorized, apiError(oauthClientSecretEmpty))
		return
	}

	apis := gw.getApisForOauthClientId(clientId, orgId)
	if len(apis) == 0 {
		//if api is 0 is because the client wasn't found
		doJSONWrite(w, http.StatusNotFound, apiError("oauth client doesn't exist"))
		return
	}

	tokens := []string{}
	for _, apiId := range apis {
		storage, _, err := gw.GetStorageForApi(apiId)
		if err == nil {
			_, tokensRevoked, _ := RevokeAllTokens(storage, clientId, clientSecret)
			tokens = append(tokens, tokensRevoked...)
		}
	}

	n := Notification{
		Command: KeySpaceUpdateNotification,
		Payload: strings.Join(tokens, ","),
		Gw:      gw,
	}
	gw.MainNotifier.Notify(n)

	doJSONWrite(w, http.StatusOK, apiOk("tokens revoked successfully"))
}

func (gw *Gateway) validateOAS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqBodyInBytes, oasObj, err := extractOASObjFromReq(r.Body)

		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		if strings.HasSuffix(r.URL.Path, "/import") && oasObj.GetTykExtension() != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(apidef.ErrImportWithTykExtension.Error()))
			return
		}

		if (r.Method == http.MethodPost || r.Method == http.MethodPut) && !strings.HasSuffix(r.URL.Path, "/import") && oasObj.GetTykExtension() == nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(apidef.ErrPayloadWithoutTykExtension.Error()))
			return
		}

		if err = oas.ValidateOASObject(reqBodyInBytes, oasObj.OpenAPI); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		if err = oasObj.Validate(r.Context(), oas.GetValidationOptionsFromConfig(gw.GetConfig().OAS)...); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(reqBodyInBytes))
		next.ServeHTTP(w, r)
	}
}

func (gw *Gateway) blockInDashboardMode(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gw.GetConfig().UseDBAppConfigs {
			doJSONWrite(w, http.StatusInternalServerError, apiError("Due to enabled use_db_app_configs, please use the Dashboard API"))
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (gw *Gateway) makeImportedOASTykAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, oasObj, err := extractOASObjFromReq(r.Body)
		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError("Couldn't decode OAS object"))
			return
		}

		tykExtensionConfigParams := oas.GetTykExtensionConfigParams(r)
		if tykExtensionConfigParams == nil {
			tykExtensionConfigParams = &oas.TykExtensionConfigParams{}
		}

		err = oasObj.BuildDefaultTykExtension(*tykExtensionConfigParams, true)
		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		oasObj.GetTykExtension().Server.ListenPath.Strip = true

		apiInBytes, err := oasObj.MarshalJSON()
		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(apiInBytes))
		next.ServeHTTP(w, r)
	}
}

// TODO: Don't modify http.Request values in-place. We must right now
// because our middleware design doesn't pass around http.Request
// pointers, so we have no way to modify the pointer in a middleware.
//
// If we ever redesign middlewares - or if we find another workaround -
// revisit this.
func setContext(r *http.Request, ctx context.Context) {
	r2 := r.WithContext(ctx)
	*r = *r2
}
func setCtxValue(r *http.Request, key, val interface{}) {
	setContext(r, context.WithValue(r.Context(), key, val))
}

func ctxGetData(r *http.Request) map[string]interface{} {
	if v := r.Context().Value(ctx.ContextData); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

func ctxSetData(r *http.Request, m map[string]interface{}) {
	if m == nil {
		panic("setting a nil context ContextData")
	}
	setCtxValue(r, ctx.ContextData, m)
}

// ctxSetCacheOptions sets a cache key to use for the http request
func ctxSetCacheOptions(r *http.Request, options *cacheOptions) {
	setCtxValue(r, ctx.CacheOptions, options)
}

// ctxGetCacheOptions returns a cache key if we need to cache request
func ctxGetCacheOptions(r *http.Request) *cacheOptions {
	key, _ := r.Context().Value(ctx.CacheOptions).(*cacheOptions)
	return key
}

func ctxGetSession(r *http.Request) *user.SessionState {
	return ctx.GetSession(r)
}

func ctxSetSession(r *http.Request, s *user.SessionState, scheduleUpdate bool, hashKey bool) {
	ctx.SetSession(r, s, scheduleUpdate, hashKey)
}

func ctxScheduleSessionUpdate(r *http.Request) {
	setCtxValue(r, ctx.UpdateSession, true)
}

func ctxDisableSessionUpdate(r *http.Request) {
	setCtxValue(r, ctx.UpdateSession, false)
}

func ctxSessionUpdateScheduled(r *http.Request) bool {
	if v := r.Context().Value(ctx.UpdateSession); v != nil {
		return v.(bool)
	}
	return false
}

func ctxGetAuthToken(r *http.Request) string {
	return ctx.GetAuthToken(r)
}

func ctxGetTrackedPath(r *http.Request) string {
	if v := r.Context().Value(ctx.TrackThisEndpoint); v != nil {
		return v.(string)
	}
	return ""
}

func ctxSetTrackedPath(r *http.Request, p string) {
	if p == "" {
		panic("setting a nil context TrackThisEndpoint")
	}
	setCtxValue(r, ctx.TrackThisEndpoint, p)
}

func ctxGetDoNotTrack(r *http.Request) bool {
	return r.Context().Value(ctx.DoNotTrackThisEndpoint) == true
}

func ctxSetDoNotTrack(r *http.Request, b bool) {
	setCtxValue(r, ctx.DoNotTrackThisEndpoint, b)
}

func ctxGetVersionInfo(r *http.Request) *apidef.VersionInfo {
	if v := r.Context().Value(ctx.VersionData); v != nil {
		return v.(*apidef.VersionInfo)
	}
	return nil
}

func ctxSetVersionInfo(r *http.Request, v *apidef.VersionInfo) {
	setCtxValue(r, ctx.VersionData, v)
}

func ctxGetVersionName(r *http.Request) *string {
	if v := r.Context().Value(ctx.VersionName); v != nil {
		return v.(*string)
	}

	return nil
}

func ctxSetVersionName(r *http.Request, vName *string) {
	setCtxValue(r, ctx.VersionName, vName)
}

func ctxSetOrigRequestURL(r *http.Request, url *url.URL) {
	setCtxValue(r, ctx.OrigRequestURL, url)
}

func ctxGetOrigRequestURL(r *http.Request) *url.URL {
	if v := r.Context().Value(ctx.OrigRequestURL); v != nil {
		if urlVal, ok := v.(*url.URL); ok {
			return urlVal
		}
	}

	return nil
}

func ctxSetURLRewriteTarget(r *http.Request, url *url.URL) {
	setCtxValue(r, ctx.UrlRewriteTarget, url)
}

func ctxGetURLRewriteTarget(r *http.Request) *url.URL {
	if v := r.Context().Value(ctx.UrlRewriteTarget); v != nil {
		if urlVal, ok := v.(*url.URL); ok {
			return urlVal
		}
	}

	return nil
}

func ctxSetUrlRewritePath(r *http.Request, path string) {
	setCtxValue(r, ctx.UrlRewritePath, path)
}

func ctxGetUrlRewritePath(r *http.Request) string {
	if v := r.Context().Value(ctx.UrlRewritePath); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return ""
}

func ctxSetCheckLoopLimits(r *http.Request, b bool) {
	setCtxValue(r, ctx.CheckLoopLimits, b)
}

// Should we check Rate limits and Quotas?
func ctxCheckLimits(r *http.Request) bool {
	// If looping disabled, allow all
	if !ctxLoopingEnabled(r) {
		return true
	}

	if v := r.Context().Value(ctx.CheckLoopLimits); v != nil {
		return v.(bool)
	}

	return false
}

func ctxSetRequestMethod(r *http.Request, path string) {
	setCtxValue(r, ctx.RequestMethod, path)
}

func ctxGetRequestMethod(r *http.Request) string {
	if v := r.Context().Value(ctx.RequestMethod); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return r.Method
}

func ctxSetTransformRequestMethod(r *http.Request, path string) {
	setCtxValue(r, ctx.TransformedRequestMethod, path)
}

func ctxGetTransformRequestMethod(r *http.Request) string {
	if v := r.Context().Value(ctx.TransformedRequestMethod); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return r.Method
}

func ctxSetGraphQLRequest(r *http.Request, gqlRequest *gql.Request) {
	setCtxValue(r, ctx.GraphQLRequest, gqlRequest)
}

func ctxGetGraphQLRequest(r *http.Request) (gqlRequest *gql.Request) {
	if v := r.Context().Value(ctx.GraphQLRequest); v != nil {
		if gqlRequest, ok := v.(*gql.Request); ok {
			return gqlRequest
		}
	}
	return nil
}

func ctxSetGraphQLIsWebSocketUpgrade(r *http.Request, isWebSocketUpgrade bool) {
	setCtxValue(r, ctx.GraphQLIsWebSocketUpgrade, isWebSocketUpgrade)
}

func ctxGetGraphQLIsWebSocketUpgrade(r *http.Request) (isWebSocketUpgrade bool) {
	if v := r.Context().Value(ctx.GraphQLIsWebSocketUpgrade); v != nil {
		if isWebSocketUpgrade, ok := v.(bool); ok {
			return isWebSocketUpgrade
		}
	}

	return false
}

func ctxGetDefaultVersion(r *http.Request) bool {
	return r.Context().Value(ctx.VersionDefault) != nil
}

func ctxSetDefaultVersion(r *http.Request) {
	setCtxValue(r, ctx.VersionDefault, true)
}

func ctxLoopingEnabled(r *http.Request) bool {
	return ctxLoopLevel(r) > 0
}

func ctxLoopLevel(r *http.Request) int {
	if v := r.Context().Value(ctx.LoopLevel); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetLoopLevel(r *http.Request, value int) {
	setCtxValue(r, ctx.LoopLevel, value)
}

func ctxIncLoopLevel(r *http.Request, loopLimit int) {
	ctxSetLoopLimit(r, loopLimit)
	ctxSetLoopLevel(r, ctxLoopLevel(r)+1)
}

func ctxLoopLevelLimit(r *http.Request) int {
	if v := r.Context().Value(ctx.LoopLevelLimit); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetLoopLimit(r *http.Request, limit int) {
	// Can be set only one time per request
	if ctxLoopLevelLimit(r) == 0 && limit > 0 {
		setCtxValue(r, ctx.LoopLevelLimit, limit)
	}
}

func ctxThrottleLevelLimit(r *http.Request) int {
	if v := r.Context().Value(ctx.ThrottleLevelLimit); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxThrottleLevel(r *http.Request) int {
	if v := r.Context().Value(ctx.ThrottleLevel); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetThrottleLimit(r *http.Request, limit int) {
	// Can be set only one time per request
	if ctxThrottleLevelLimit(r) == 0 && limit > 0 {
		setCtxValue(r, ctx.ThrottleLevelLimit, limit)
	}
}

func ctxSetThrottleLevel(r *http.Request, value int) {
	setCtxValue(r, ctx.ThrottleLevel, value)
}

func ctxIncThrottleLevel(r *http.Request, throttleLimit int) {
	ctxSetThrottleLimit(r, throttleLimit)
	ctxSetThrottleLevel(r, ctxThrottleLevel(r)+1)
}





func ctxSetSpanAttributes(r *http.Request, mwName string, attrs ...otel.SpanAttribute) {
	if len(attrs) > 0 {
		setCtxValue(r, mwName, attrs)
	}
}

func ctxGetSpanAttributes(r *http.Request, mwName string) (attrs []otel.SpanAttribute) {
	if v := r.Context().Value(mwName); v != nil {
		got, ok := v.([]otel.SpanAttribute)
		if ok {
			attrs = got
		}
	}
	return
}

func ctxSetRequestStatus(r *http.Request, stat RequestStatus) {
	setCtxValue(r, ctx.RequestStatus, stat)
}

func ctxGetRequestStatus(r *http.Request) (stat RequestStatus) {
	if v := r.Context().Value(ctx.RequestStatus); v != nil {
		stat = v.(RequestStatus)
	}
	return
}

func ctxSetOperation(r *http.Request, op *Operation) {
	setCtxValue(r, ctx.OASOperation, op)
}

func ctxGetOperation(r *http.Request) (op *Operation) {
	if v := r.Context().Value(ctx.OASOperation); v != nil {
		op = v.(*Operation)
	}
	return
}

var createOauthClientSecret = func() string {
	secret := uuid.New()
	return base64.StdEncoding.EncodeToString([]byte(secret))
}

// invalidate tokens if we had a new policy
// Example of adding error handling for mw.ApplyPolicies
// Assuming mw.ApplyPolicies returns an error
result, err := mw.ApplyPolicies(policyArgs)
if err != nil {
	log.Errorf("Failed to apply policies: %v", err)
	return err
}

// Example of adding error handling for strconv.Atoi
intValue, err := strconv.Atoi(stringValue)
if err != nil {
	log.Errorf("Failed to convert string to int: %v", err)
	return err
}

// Example of adding error handling for json.Unmarshal
err = json.Unmarshal(data, &targetStruct)
if err != nil {
	log.Errorf("Failed to unmarshal JSON: %v", err)
	return err
}

// Example of adding error handling for os.Remove
err = os.Remove(filePath)
if err != nil {
	log.Errorf("Failed to remove file: %v", err)
	return err
}

func extractOASObjFromReq(reqBody io.Reader) ([]byte, *oas.OAS, error) {
	var oasObj oas.OAS
reqBodyInBytes, err := io.ReadAll(reqBody)
if err != nil {
    return nil, nil, ErrRequestMalformed
}

loader := openapi3.NewLoader()
t, err := loader.LoadFromData(reqBodyInBytes)
if err != nil {
    return nil, nil, ErrRequestMalformed
}

oasObj.T = *t

r.Body = io.NopCloser(bytes.NewReader(reqBodyInBytes))
}

func validateAPIDef(apiDef *apidef.APIDefinition) *apiStatusMessage {
	validationResult := apidef.Validate(apiDef, apidef.DefaultValidationRuleSet)
	if !validationResult.IsValid {
		reason := "unknown"
		if validationResult.ErrorCount() > 0 {
			reason = validationResult.FirstError().Error()
		}

		apiErr := apiError(fmt.Sprintf("Validation of API Definition failed. Reason: %s.", reason))
		return &apiErr
	}

	return nil
}

func updateOASServers(spec *APISpec, conf config.Config, apiDef *apidef.APIDefinition, oasObj *oas.OAS) {
	var oldAPIURL string
	if spec != nil && spec.OAS.Servers != nil {
		oldAPIURL = spec.OAS.Servers[0].URL
	}

	newAPIURL := getAPIURL(*apiDef, conf)
	oasObj.UpdateServers(newAPIURL, oldAPIURL)
}
