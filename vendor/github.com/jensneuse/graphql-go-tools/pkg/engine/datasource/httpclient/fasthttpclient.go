package httpclient

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/buger/jsonparser"
	"github.com/jensneuse/abstractlogger"
	"github.com/valyala/fasthttp"

	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type FastHttpClient struct {
	client *fasthttp.Client
	log    abstractlogger.Logger
}

type Option func(c *FastHttpClient)

func WithLogger(logger abstractlogger.Logger) Option {
	return func(c *FastHttpClient) {
		c.log = logger
	}
}

func NewFastHttpClient(client *fasthttp.Client, options ...Option) *FastHttpClient {
	c := &FastHttpClient{
		client: client,
	}
	for i := range options {
		options[i](c)
	}
	return c
}

var (
	DefaultFastHttpClient = &fasthttp.Client{
		ReadTimeout:         time.Second * 10,
		WriteTimeout:        time.Second * 10,
		MaxIdleConnDuration: time.Minute,
	}
	queryParamsKeys = [][]string{
		{"name"},
		{"value"},
	}
	applicationJsonBytes = []byte("application/json")
	acceptBytes          = []byte("accept")
	acceptEncodingBytes  = []byte("Accept-Encoding")
	gzipEncodingBytes    = []byte("gzip")
	userAgentBytes       = []byte("graphql-go-client")
	contentEncoding      = []byte("Content-Encoding")
)

func (f *FastHttpClient) Do(ctx context.Context, requestInput []byte, out io.Writer) (err error) {

	var (
		responseBody []byte
	)

	url, method, body, headers, queryParams := requestInputParams(requestInput)

	req, res := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		if f.log != nil {
			f.log.Debug("FastHttpClient.do",
				abstractlogger.ByteString("requestInput", requestInput),
				abstractlogger.ByteString("requestURI", req.RequestURI()),
				abstractlogger.ByteString("requestHeader", req.Header.Header()),
				abstractlogger.Int("responseCode", res.StatusCode()),
				abstractlogger.ByteString("responseHeader", res.Header.Header()),
				abstractlogger.ByteString("responseBody", responseBody),
			)
		}
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(res)
	}()

	req.Header.SetUserAgentBytes(userAgentBytes)
	req.Header.SetMethodBytes(method)
	req.SetRequestURIBytes(url)
	req.SetBody(body)

	if headers != nil {
		err = jsonparser.ObjectEach(headers, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
			req.Header.SetBytesKV(key, value)
			return nil
		})
		if err != nil {
			return err
		}
	}

	if queryParams != nil {
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
						req.URI().QueryArgs().AddBytesKV(parameterName, value)
					})
				} else {
					req.URI().QueryArgs().AddBytesKV(parameterName, parameterValue)
				}
			}
		})
		if err != nil {
			return err
		}
	}

	req.Header.SetBytesKV(acceptBytes, applicationJsonBytes)
	req.Header.SetBytesKV(acceptEncodingBytes, gzipEncodingBytes)
	req.Header.SetContentTypeBytes(applicationJsonBytes)

	if deadline, ok := ctx.Deadline(); ok {
		err = f.client.DoDeadline(req, res, deadline)
	} else {
		err = f.client.Do(req, res)
	}

	if err != nil {
		return
	}

	if bytes.Equal(res.Header.PeekBytes(contentEncoding), gzipEncodingBytes) {
		responseBody, err = res.BodyGunzip()
		if err != nil {
			return err
		}
	} else {
		responseBody = res.Body()
	}

	_, err = out.Write(responseBody)
	return err
}
