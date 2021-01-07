package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/buger/jsonparser"
	byte_template "github.com/jensneuse/byte-template"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/quotes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

const (
	PATH        = "path"
	URL         = "url"
	BASEURL     = "base_url"
	METHOD      = "method"
	BODY        = "body"
	HEADERS     = "headers"
	QUERYPARAMS = "query_params"

	SCHEME = "scheme"
	HOST   = "host"
)

var (
	inputPaths = [][]string{
		{URL},
		{METHOD},
		{BODY},
		{HEADERS},
		{QUERYPARAMS},
	}
	subscriptionInputPaths = [][]string{
		{SCHEME},
		{HOST},
		{BODY},
		{HEADERS},
		{PATH},
	}
)

type Client interface {
	Do(ctx context.Context, requestInput []byte, out io.Writer) (err error)
}

func wrapQuotesIfString(b []byte) []byte {

	if bytes.HasPrefix(b, []byte("$$")) && bytes.HasSuffix(b, []byte("$$")) {
		return b
	}

	if bytes.HasPrefix(b, []byte("{{")) && bytes.HasSuffix(b, []byte("}}")) {
		return b
	}

	inType := gjson.ParseBytes(b).Type
	switch inType {
	case gjson.Number, gjson.String:
		return b
	case gjson.JSON:
		var value interface{}
		withoutTemplate := bytes.ReplaceAll(b, []byte("$$"), nil)

		buf := &bytes.Buffer{}
		tmpl := byte_template.New()
		_, _ = tmpl.Execute(buf, withoutTemplate, func(w io.Writer, path []byte) (n int, err error) {
			return w.Write([]byte("0"))
		})

		withoutTemplate = buf.Bytes()

		err := json.Unmarshal(withoutTemplate, &value)
		if err == nil {
			return b
		}
	case gjson.False:
		if bytes.Equal(b, literal.FALSE) {
			return b
		}
	case gjson.True:
		if bytes.Equal(b, literal.TRUE) {
			return b
		}
	case gjson.Null:
		if bytes.Equal(b, literal.NULL) {
			return b
		}
	}
	return quotes.WrapBytes(b)
}

func SetInputURL(input, url []byte) []byte {
	if len(url) == 0 {
		return input
	}
	out, _ := sjson.SetRawBytes(input, URL, wrapQuotesIfString(url))
	return out
}

func SetInputMethod(input, method []byte) []byte {
	if len(method) == 0 {
		return input
	}
	out, _ := sjson.SetRawBytes(input, METHOD, wrapQuotesIfString(method))
	return out
}

func SetInputBody(input, body []byte) []byte {
	return SetInputBodyWithPath(input, body, "")
}

func SetInputBodyWithPath(input, body []byte, path string) []byte {
	if len(body) == 0 {
		return input
	}
	if path != "" {
		path = BODY + "." + path
	} else {
		path = BODY
	}
	out, _ := sjson.SetRawBytes(input, path, wrapQuotesIfString(body))
	return out
}

func SetInputHeaders(input, headers []byte) []byte {
	if len(headers) == 0 {
		return input
	}
	out, _ := sjson.SetRawBytes(input, HEADERS, wrapQuotesIfString(headers))
	return out
}

func SetInputQueryParams(input, queryParams []byte) []byte {
	if len(queryParams) == 0 {
		return input
	}
	out, _ := sjson.SetRawBytes(input, QUERYPARAMS, wrapQuotesIfString(queryParams))
	return out
}

func SetInputScheme(input, scheme []byte) []byte {
	if len(scheme) == 0 {
		return input
	}
	out, _ := sjson.SetRawBytes(input, SCHEME, wrapQuotesIfString(scheme))
	return out
}

func SetInputHost(input, host []byte) []byte {
	if len(host) == 0 {
		return input
	}
	out, _ := sjson.SetRawBytes(input, HOST, wrapQuotesIfString(host))
	return out
}

func SetInputPath(input, path []byte) []byte {
	if len(path) == 0 {
		return input
	}
	out, _ := sjson.SetRawBytes(input, PATH, wrapQuotesIfString(path))
	return out
}

func requestInputParams(input []byte) (url, method, body, headers, queryParams []byte) {
	jsonparser.EachKey(input, func(i int, bytes []byte, valueType jsonparser.ValueType, err error) {
		switch i {
		case 0:
			url = bytes
		case 1:
			method = bytes
		case 2:
			body = bytes
		case 3:
			headers = bytes
		case 4:
			queryParams = bytes
		}
	}, inputPaths...)
	return
}

func GetSubscriptionInput(input []byte) (scheme, host, path, body, headers []byte) {
	jsonparser.EachKey(input, func(i int, bytes []byte, valueType jsonparser.ValueType, err error) {
		switch i {
		case 0:
			scheme = bytes
		case 1:
			host = bytes
		case 2:
			body = bytes
		case 3:
			headers = bytes
		case 4:
			path = bytes
		}
	}, subscriptionInputPaths...)
	return
}
