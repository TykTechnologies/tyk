package httputil

import "net/http"

// IsTransferEncodingChunked checks that a http.Request is not
// chunked. Requests with this transfer encoding do not include
// a valid Content-Length header.
func IsTransferEncodingChunked(req *http.Request) bool {
	for _, val := range req.TransferEncoding {
		if val == "chunked" {
			return true
		}
	}
	return false
}
