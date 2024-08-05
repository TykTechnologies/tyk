package gateway

// modeSpecificSpec returns the respective field of URLSpec if it matches the given mode.
// Deprecated: Usage should not increase.
func (u *URLSpec) modeSpecificSpec(mode URLStatus) (interface{}, bool) {
	switch mode {
	case Ignored, BlackList, WhiteList:
		return nil, true
	case Cached:
		return &u.CacheConfig, true
	case Transformed:
		return &u.TransformAction, true
	case TransformedJQ:
		return &u.TransformJQAction, true
	case HeaderInjected:
		return &u.InjectHeaders, true
	case HeaderInjectedResponse:
		return &u.InjectHeadersResponse, true
	case TransformedResponse:
		return &u.TransformResponseAction, true
	case TransformedJQResponse:
		return &u.TransformJQResponseAction, true
	case HardTimeout:
		return &u.HardTimeout.TimeOut, true
	case CircuitBreaker:
		return &u.CircuitBreaker, true
	case URLRewrite:
		return u.URLRewrite, true
	case VirtualPath:
		return &u.VirtualPathSpec, true
	case RequestSizeLimit:
		return &u.RequestSize, true
	case MethodTransformed:
		return &u.MethodTransform, true
	case RequestTracked:
		return &u.TrackEndpoint, true
	case RequestNotTracked:
		return &u.DoNotTrackEndpoint, true
	case ValidateJSONRequest:
		return &u.ValidatePathMeta, true
	case Internal:
		return &u.Internal, true
	case GoPlugin:
		return &u.GoPluginMeta, true
	case PersistGraphQL:
		return &u.PersistGraphQL, true
	default:
		return nil, false
	}
}

// matchesMethod checks if the given method matches the method required by the URLSpec for the current status.
func (u *URLSpec) matchesMethod(method string) bool {
	switch u.Status {
	case Ignored, BlackList, WhiteList:
		return true
	case Cached:
		return method == u.CacheConfig.Method || (u.CacheConfig.Method == SAFE_METHODS && isSafeMethod(method))
	case Transformed:
		return method == u.TransformAction.Method
	case TransformedJQ:
		return method == u.TransformJQAction.Method
	case HeaderInjected:
		return method == u.InjectHeaders.Method
	case HeaderInjectedResponse:
		return method == u.InjectHeadersResponse.Method
	case TransformedResponse:
		return method == u.TransformResponseAction.Method
	case TransformedJQResponse:
		return method == u.TransformJQResponseAction.Method
	case HardTimeout:
		return method == u.HardTimeout.Method
	case CircuitBreaker:
		return method == u.CircuitBreaker.Method
	case URLRewrite:
		return method == u.URLRewrite.Method
	case VirtualPath:
		return method == u.VirtualPathSpec.Method
	case RequestSizeLimit:
		return method == u.RequestSize.Method
	case MethodTransformed:
		return method == u.MethodTransform.Method
	case RequestTracked:
		return method == u.TrackEndpoint.Method
	case RequestNotTracked:
		return method == u.DoNotTrackEndpoint.Method
	case ValidateJSONRequest:
		return method == u.ValidatePathMeta.Method
	case Internal:
		return method == u.Internal.Method
	case GoPlugin:
		return method == u.GoPluginMeta.Meta.Method
	case PersistGraphQL:
		return method == u.PersistGraphQL.Method
	case RateLimit:
		return method == u.RateLimit.Method
	default:
		return false
	}
}
