package main

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

func ExampleMyAnalyticsPluginDeleteHeader() {
	record := analytics.AnalyticsRecord{
		ContentLength: 5,
		RawResponse:   base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nServer: golang\r\nContent-Length: 5\r\n\r\nHello")),
	}
	MyAnalyticsPluginDeleteHeader(&record)
	data, _ := base64.StdEncoding.DecodeString(record.RawResponse)
	fmt.Printf("%q", string(data))
	// Output: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
}

func ExampleMyAnalyticsPluginMaskJSONLoginBody() {
	record := analytics.AnalyticsRecord{
		ContentLength: 72,
		RawRequest:    base64.StdEncoding.EncodeToString([]byte("POST / HTTP/1.1\r\nHost: server.com\r\nContent-Length: 72\r\n\r\n{\"email\": \"m\", \"password\": \"p\", \"data\": {\"email\": \"m\", \"password\": \"p\"}}")),
	}
	MyAnalyticsPluginMaskJSONLoginBody(&record)
	data, _ := base64.StdEncoding.DecodeString(record.RawRequest)
	const endOfHeaders = "\r\n\r\n"
	paths := [][]string{
		{"email"},
		{"password"},
		{"data", "email"},
		{"data", "password"},
	}
	if i := bytes.Index(data, []byte(endOfHeaders)); i > 0 || (i+4) < len(data) {
		jsonparser.EachKey(data[i+4:], func(_ int, v []byte, _ jsonparser.ValueType, _ error) {
			fmt.Println(string(v))
		}, paths...)
	}
	// Output: ****
	//****
	//****
	//****
}
