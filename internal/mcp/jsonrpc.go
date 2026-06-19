package mcp

// JSON-RPC 2.0 Error Codes as defined in the JSON-RPC 2.0 specification.
// SW-REQ-025
const (
	// JSONRPCParseError indicates invalid JSON was received by the server.
	JSONRPCParseError = -32700
	// JSONRPCInvalidRequest indicates the JSON sent is not a valid Request object.
	JSONRPCInvalidRequest = -32600
	// JSONRPCMethodNotFound indicates the method does not exist or is not available.
	JSONRPCMethodNotFound = -32601
	// JSONRPCInvalidParams indicates invalid method parameter(s).
	JSONRPCInvalidParams = -32602
	// JSONRPCInternalError indicates an internal JSON-RPC error.
	JSONRPCInternalError = -32603
	// JSONRPCServerError is the base code for server errors (-32000 to -32099).
)

// MCP JSON-RPC method names as defined in the Model Context Protocol specification.
// SW-REQ-025
const (
	// Tool methods
	MethodToolsCall = "tools/call"
	MethodToolsList = "tools/list"

	// Resource methods
	MethodResourcesRead          = "resources/read"
	MethodResourcesList          = "resources/list"
	MethodResourcesTemplatesList = "resources/templates/list"

	// Prompt methods
	MethodPromptsGet  = "prompts/get"
	MethodPromptsList = "prompts/list"
)

// JSON-RPC parameter keys used across MCP methods
// SW-REQ-025
const (
	ParamKeyName = "name" // Used by tools/call and prompts/get
	ParamKeyURI  = "uri"  // Used by resources/* methods
)

// Primitive type identifiers — mirrors user.PrimitiveType* for gateway-internal use.
// Gateway code always uses these constants; dashboard code uses user.PrimitiveType*.
// SW-REQ-025
const (
	PrimitiveTypeTool     = "tool"
	PrimitiveTypeResource = "resource"
	PrimitiveTypePrompt   = "prompt"
)

// Primitive type key prefixes for primitives map lookups
// SW-REQ-025
const (
	PrimitiveKeyTool      = "tool:"
	PrimitiveKeyResource  = "resource:"
	PrimitiveKeyPrompt    = "prompt:"
	PrimitiveKeyOperation = "operation:"
)

// Error messages for JSON-RPC responses
// SW-REQ-025
const (
	ErrMsgParseError     = "parse error"
	ErrMsgInvalidRequest = "invalid request"
	ErrMsgInvalidParams  = "invalid params"
)

// Detailed error messages for invalid params scenarios
// SW-REQ-025
const (
	ErrMsgMissingParams     = "missing required params object"
	ErrMsgMissingParamName  = "missing required parameter: name"
	ErrMsgMissingParamURI   = "missing required parameter: uri"
	ErrMsgEmptyParamName    = "parameter 'name' cannot be empty"
	ErrMsgEmptyParamURI     = "parameter 'uri' cannot be empty"
	ErrMsgInvalidParamsType = "invalid params: expected object"
)
