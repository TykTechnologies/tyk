package apimetrics

import (
	"fmt"
	"strconv"
	"strings"
)

// DimensionExtractor extracts a single OTel attribute value from the request context.
type DimensionExtractor struct {
	Label   string                          // OTel attribute name in exported data
	Default string                          // fallback when source is empty
	Extract func(rc *RequestContext) string // extraction function
}

// CompileExtractor creates a DimensionExtractor from a DimensionDefinition.
// Called once at startup per dimension.
func CompileExtractor(dim DimensionDefinition) (*DimensionExtractor, error) {
	label := dim.Label
	if label == "" {
		label = dim.Key
	}

	ext := &DimensionExtractor{
		Label:   label,
		Default: dim.Default,
	}

	switch dim.Source {
	case "metadata":
		fn, ok := metadataExtractors[dim.Key]
		if !ok {
			return nil, fmt.Errorf("unknown metadata key: %q", dim.Key)
		}
		ext.Extract = fn

	case "session":
		fn, ok := sessionExtractors[dim.Key]
		if !ok {
			return nil, fmt.Errorf("unknown session key: %q", dim.Key)
		}
		ext.Extract = fn

	case "header":
		key := dim.Key
		ext.Extract = func(rc *RequestContext) string {
			if rc.Request == nil {
				return ""
			}
			return rc.Request.Header.Get(key)
		}

	case "context":
		key := dim.Key
		ext.Extract = func(rc *RequestContext) string {
			if rc.ContextVariables == nil {
				return ""
			}
			if v, ok := rc.ContextVariables[key]; ok {
				return fmt.Sprint(v)
			}
			return ""
		}

	case "response_header":
		key := dim.Key
		ext.Extract = func(rc *RequestContext) string {
			if rc.Response == nil {
				return ""
			}
			return rc.Response.Header.Get(key)
		}

	case "config_data":
		key := dim.Key
		ext.Extract = func(rc *RequestContext) string {
			if rc.ConfigData == nil {
				return ""
			}
			if v, ok := rc.ConfigData[key]; ok {
				return fmt.Sprint(v)
			}
			return ""
		}

	default:
		return nil, fmt.Errorf("unknown dimension source: %q", dim.Source)
	}

	return ext, nil
}

// metadataExtractors maps metadata keys to extraction functions.
var metadataExtractors = map[string]func(rc *RequestContext) string{
	"method": func(rc *RequestContext) string {
		if rc.Request == nil {
			return ""
		}
		return rc.Request.Method
	},
	"response_code": func(rc *RequestContext) string {
		return strconv.Itoa(rc.StatusCode)
	},
	"listen_path": func(rc *RequestContext) string {
		return rc.ListenPath
	},
	"endpoint": func(rc *RequestContext) string {
		return rc.Endpoint
	},
	"api_id": func(rc *RequestContext) string {
		return rc.APIID
	},
	"api_name": func(rc *RequestContext) string {
		return rc.APIName
	},
	"org_id": func(rc *RequestContext) string {
		return rc.OrgID
	},
	"response_flag": func(rc *RequestContext) string {
		if rc.ErrorClassification != "" {
			return rc.ErrorClassification
		}
		return strconv.Itoa(rc.StatusCode)
	},
	"ip_address": func(rc *RequestContext) string {
		return rc.IPAddress
	},
	"api_version": func(rc *RequestContext) string {
		return rc.APIVersion
	},
	"host": func(rc *RequestContext) string {
		if rc.Request == nil {
			return ""
		}
		return rc.Request.Host
	},
	"scheme": func(rc *RequestContext) string {
		if rc.Request != nil && rc.Request.TLS != nil {
			return "https"
		}
		return "http"
	},
	"mcp_method": func(rc *RequestContext) string {
		return rc.MCPMethod
	},
	"mcp_primitive_type": func(rc *RequestContext) string {
		return rc.MCPPrimitiveType
	},
	"mcp_primitive_name": func(rc *RequestContext) string {
		return rc.MCPPrimitiveName
	},
	"mcp_error_code": func(rc *RequestContext) string {
		if rc.MCPErrorCode == 0 {
			return ""
		}
		return strconv.Itoa(rc.MCPErrorCode)
	},
}

// sessionExtractors maps session keys to extraction functions.
var sessionExtractors = map[string]func(rc *RequestContext) string{
	"api_key": func(rc *RequestContext) string {
		if rc.Token != "" {
			return truncateKey(rc.Token)
		}
		return ""
	},
	"oauth_id": func(rc *RequestContext) string {
		if rc.Session != nil {
			return rc.Session.OauthClientID
		}
		return ""
	},
	"alias": func(rc *RequestContext) string {
		if rc.Session != nil {
			return rc.Session.Alias
		}
		return ""
	},
	"portal_app": func(rc *RequestContext) string {
		if rc.Session != nil {
			for _, tag := range rc.Session.Tags {
				if v, ok := strings.CutPrefix(tag, "portal-app-"); ok {
					return v
				}
			}
		}
		return ""
	},
	"portal_org": func(rc *RequestContext) string {
		if rc.Session != nil {
			for _, tag := range rc.Session.Tags {
				if v, ok := strings.CutPrefix(tag, "portal-org-"); ok {
					return v
				}
			}
		}
		return ""
	},
}

// truncateKey returns the last 6 characters of the token for cardinality control.
func truncateKey(token string) string {
	if len(token) > 6 {
		return token[len(token)-6:]
	}
	return token
}
