package gateway

// SSEHook allows middleware to intercept individual SSE events as they flow
// through the gateway. Hooks are invoked by SSETap for every parsed event.
type SSEHook interface {
	// FilterEvent inspects an SSE event and decides whether it should be
	// forwarded to the downstream client.
	//
	// Return values:
	//   - allowed: if false the event is silently dropped.
	//   - modifiedEvent: if non-nil it replaces the original event in the
	//     output stream. Ignored when allowed is false.
	FilterEvent(event *SSEEvent) (allowed bool, modifiedEvent *SSEEvent)
}
