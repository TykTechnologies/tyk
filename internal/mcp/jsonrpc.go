package mcp

// JSON-RPC 2.0 Error Codes as defined in the JSON-RPC 2.0 specification.
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
const (
	// Tool methods
	MethodToolsCall = "tools/call"

	// Resource methods
	MethodResourcesRead = "resources/read"

	// Prompt methods
	MethodPromptsGet = "prompts/get"
)

// JSON-RPC parameter keys used across MCP methods
const (
	ParamKeyName = "name" // Used by tools/call and prompts/get
	ParamKeyURI  = "uri"  // Used by resources/* methods
)

// Primitive type key prefixes for primitives map lookups
const (
	PrimitiveKeyTool      = "tool:"
	PrimitiveKeyResource  = "resource:"
	PrimitiveKeyPrompt    = "prompt:"
	PrimitiveKeyOperation = "operation:"
)

// Error messages for JSON-RPC responses
const (
	ErrMsgParseError     = "Parse Error"
	ErrMsgInvalidRequest = "Invalid Request"
	ErrMsgInvalidParams  = "Invalid Params"
)

// Detailed error messages for invalid params scenarios
const (
	ErrMsgMissingParams     = "Missing required params object"
	ErrMsgMissingParamName  = "Missing required parameter: name"
	ErrMsgMissingParamURI   = "Missing required parameter: uri"
	ErrMsgEmptyParamName    = "Parameter 'name' cannot be empty"
	ErrMsgEmptyParamURI     = "Parameter 'uri' cannot be empty"
	ErrMsgInvalidParamsType = "Invalid params: expected object"
)
