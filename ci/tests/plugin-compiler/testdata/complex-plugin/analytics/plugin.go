package analytics

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net/http"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

func MyAnalyticsPluginDeleteHeader(record *analytics.AnalyticsRecord) {
	str, err := base64.StdEncoding.DecodeString(record.RawResponse)
	if err != nil {
		return
	}

	var b = &bytes.Buffer{}
	b.Write(str)

	r := bufio.NewReader(b)
	var resp *http.Response
	resp, err = http.ReadResponse(r, nil)
	if err != nil {
		return
	}
	resp.Header.Del("Server")
	var bNew bytes.Buffer
	_ = resp.Write(&bNew)
	record.RawResponse = base64.StdEncoding.EncodeToString(bNew.Bytes())
}

func MyAnalyticsPluginMaskJSONLoginBody(record *analytics.AnalyticsRecord) {
	if record.ContentLength < 1 {
		return
	}
	d, err := base64.StdEncoding.DecodeString(record.RawRequest)
	if err != nil {
		return
	}
	var mask = []byte("\"****\"")
	const endOfHeaders = "\r\n\r\n"
	paths := [][]string{
		{"email"},
		{"password"},
		{"data", "email"},
		{"data", "password"},
	}
	if i := bytes.Index(d, []byte(endOfHeaders)); i > 0 || (i+4) < len(d) {
		body := d[i+4:]
		jsonparser.EachKey(body, func(idx int, _ []byte, _ jsonparser.ValueType, _ error) {
			body, _ = jsonparser.Set(body, mask, paths[idx]...)
		}, paths...)
		if err == nil {
			record.RawRequest = base64.StdEncoding.EncodeToString(append(d[:i+4], body...))
		}
	}
}
