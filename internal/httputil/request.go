package httputil

import "net/http"

// TransferEncoding gets the header value from the request.
func TransferEncoding(req *http.Request) string {
	for _, val := range req.TransferEncoding {
		if val != "" {
			return val
		}
	}
	return ""
}

// HasTransferEncoding returns true if a transfer encoding header is present.
func HasTransferEncoding(req *http.Request) bool {
	return TransferEncoding(req) != ""
}
