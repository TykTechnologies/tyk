package httpclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/buger/jsonparser"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type NetHttpClient struct {
	client *http.Client
}

func NewNetHttpClient(client *http.Client) *NetHttpClient {
	return &NetHttpClient{
		client: client,
	}
}

var (
	DefaultNetHttpClient = &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1024,
			TLSHandshakeTimeout: 0 * time.Second,
		},
	}
)

func (n *NetHttpClient) Do(ctx context.Context, requestInput []byte, out io.Writer) (err error) {

	url, method, body, headers, queryParams := requestInputParams(requestInput)

	// Change to `http.NewRequestWithContext` when support for go 1.12 is dropped
	request, err := NewRequestWithContext(ctx, unsafebytes.BytesToString(method), unsafebytes.BytesToString(url), bytes.NewReader(body))
	if err != nil {
		return err
	}

	if headers != nil {
		err = jsonparser.ObjectEach(headers, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
			_, err := jsonparser.ArrayEach(value, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				if err != nil {
					return
				}
				request.Header.Add(unsafebytes.BytesToString(key), unsafebytes.BytesToString(value))
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

	response, err := n.client.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	_, err = io.Copy(out, response.Body)
	return
}
