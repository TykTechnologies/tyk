package httputil

import (
	"net/http"

	"github.com/TykTechnologies/tyk/header"
)

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

// IsStreaming returns true if the request is a streaming request.
func IsStreaming(r *http.Request) bool {
	return r.ContentLength == -1
}

// IsGrpcStreaming returns true if the request is a gRPC streaming request.
func IsGrpcStreaming(r *http.Request) bool {
	return IsStreaming(r) && r.Header.Get(header.ContentType) == "application/grpc"
}
