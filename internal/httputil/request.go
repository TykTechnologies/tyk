package httputil

import (
	"bytes"
	"encoding/base64"
	"net/http"
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

// EncodeRequest will write the request out in wire protocol and return
// it it as a base64 encoded string.
func EncodeRequest(r *http.Request) string {
	var asBytes bytes.Buffer
	r.Write(&asBytes)

	return base64.StdEncoding.EncodeToString(asBytes.Bytes())
}
