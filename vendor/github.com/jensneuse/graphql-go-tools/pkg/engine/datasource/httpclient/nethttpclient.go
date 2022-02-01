package httpclient

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/buger/jsonparser"

	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

const (
	ContentEncodingHeader = "Content-Encoding"
	AcceptEncodingHeader  = "Accept-Encoding"
)

var (
	DefaultNetHttpClient = &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1024,
			TLSHandshakeTimeout: 0 * time.Second,
		},
	}
	queryParamsKeys = [][]string{
		{"name"},
		{"value"},
	}
)

func Do(client *http.Client, ctx context.Context, requestInput []byte, out io.Writer) (err error) {

	url, method, body, headers, queryParams := requestInputParams(requestInput)

	request, err := http.NewRequestWithContext(ctx, string(method), string(url), bytes.NewReader(body))
	if err != nil {
		return err
	}

	if headers != nil {
		err = jsonparser.ObjectEach(headers, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
			_, err := jsonparser.ArrayEach(value, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				if err != nil {
					return
				}
				request.Header.Add(string(key), string(value))
			})
			return err
		})
		if err != nil {
			return err
		}
	}

	if queryParams != nil {
		query := request.URL.Query()
		_, err = jsonparser.ArrayEach(queryParams, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			var (
				parameterName, parameterValue []byte
			)
			jsonparser.EachKey(value, func(i int, bytes []byte, valueType jsonparser.ValueType, err error) {
				switch i {
				case 0:
					parameterName = bytes
				case 1:
					parameterValue = bytes
				}
			}, queryParamsKeys...)
			if len(parameterName) != 0 && len(parameterValue) != 0 {
				if bytes.Equal(parameterValue[:1], literal.LBRACK) {
					_, _ = jsonparser.ArrayEach(parameterValue, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
						query.Add(string(parameterName), string(value))
					})
				} else {
					query.Add(string(parameterName), string(parameterValue))
				}
			}
		})
		if err != nil {
			return err
		}
		request.URL.RawQuery = query.Encode()
	}

	request.Header.Add("accept", "application/json")
	request.Header.Add("content-type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	respReader, err := respBodyReader(request, response)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, respReader)
	return
}

func respBodyReader(req *http.Request, resp *http.Response) (io.ReadCloser, error) {
	if req.Header.Get(AcceptEncodingHeader) == "" {
		return resp.Body, nil
	}

	switch resp.Header.Get(ContentEncodingHeader) {
	case "gzip":
		return gzip.NewReader(resp.Body)
	case "deflate":
		return flate.NewReader(resp.Body), nil
	}

	return resp.Body, nil
}
