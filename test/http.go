package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type TestCase struct {
	Method          string            `json:",omitempty"`
	Path            string            `json:",omitempty"`
	BaseURL         string            `json:",omitempty"`
	Domain          string            `json:",omitempty"`
	Proto           string            `json:",omitempty"`
	Code            int               `json:",omitempty"`
	Data            interface{}       `json:",omitempty"`
	Headers         map[string]string `json:",omitempty"`
	PathParams      map[string]string `json:",omitempty"`
	FormParams      map[string]string `json:",omitempty"`
	Cookies         []*http.Cookie    `json:",omitempty"`
	Delay           time.Duration     `json:",omitempty"`
	BodyMatch       string            `json:",omitempty"`
	BodyMatchFunc   func([]byte) bool `json:",omitempty"`
	BodyNotMatch    string            `json:",omitempty"`
	HeadersMatch    map[string]string `json:",omitempty"`
	HeadersNotMatch map[string]string `json:",omitempty"`
	JSONMatch       map[string]string `json:",omitempty"`
	ErrorMatch      string            `json:",omitempty"`
	BeforeFn        func()            `json:"-"`
	Client          *http.Client      `json:"-"`

	AdminAuth      bool `json:",omitempty"`
	ControlRequest bool `json:",omitempty"`
}

func AssertResponse(resp *http.Response, tc *TestCase) error {
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	defer resp.Body.Close()

	if tc.Code != 0 && resp.StatusCode != tc.Code {
		return fmt.Errorf("Expected status code `%d` got `%d. %s`", tc.Code, resp.StatusCode, string(body))
	}

	if tc.BodyMatch != "" && !bytes.Contains(body, []byte(tc.BodyMatch)) {
		return fmt.Errorf("Response body does not contain `%s`. %s", tc.BodyMatch, string(body))
	}

	if tc.BodyNotMatch != "" && bytes.Contains(body, []byte(tc.BodyNotMatch)) {
		return fmt.Errorf("Response body should not contain `%s`. %s", tc.BodyNotMatch, string(body))
	}

	if tc.BodyMatchFunc != nil && !tc.BodyMatchFunc(body) {
		return fmt.Errorf("Response body did not pass BodyMatchFunc: %s", string(body))
	}

	if tc.Proto != "" && tc.Proto != resp.Proto {
		return fmt.Errorf("Expected protocol `%s` got `%s`.", tc.Proto, resp.Proto)
	}

	for k, v := range tc.HeadersMatch {
		if resp.Header.Get(k) != v {
			return fmt.Errorf("Response header `%s` expected `%s` instead `%s`. %v", k, v, resp.Header.Get(k), resp.Header)
		}
	}

	for k, v := range tc.HeadersNotMatch {
		if resp.Header.Get(k) == v {
			return fmt.Errorf("Response header `%s` should not be %s`", k, v)
		}
	}

	if len(tc.JSONMatch) == 0 {
		return nil
	}

	var jsonBody map[string]json.RawMessage
	if err := json.Unmarshal(body, &jsonBody); err != nil {
		return fmt.Errorf("Should return JSON body: %s. %d", string(body), resp.StatusCode)
	}

	for k, expect := range tc.JSONMatch {
		if got, ok := jsonBody[k]; !ok {
			return fmt.Errorf("`%s` JSON field not found: %s", k, string(body))
		} else if string(got) != expect {
			return fmt.Errorf("`%s` not match: `%s` != `%s`", k, got, expect)
		}
	}

	return nil
}

func ReqBodyReader(body interface{}) io.Reader {
	switch x := body.(type) {
	case []byte:
		return bytes.NewReader(x)
	case string:
		return strings.NewReader(x)
	case io.Reader:
		return x
	case nil:
		return nil
	default: // JSON objects (structs)
		bs, err := json.Marshal(x)
		if err != nil {
			panic(err)
		}
		return bytes.NewReader(bs)
	}
}

func NewRequest(tc *TestCase) (req *http.Request, err error) {
	if tc.Method == "" {
		tc.Method = "GET"
	}

	if tc.Path == "" {
		tc.Path = "/"
	}

	if tc.Domain == "" {
		tc.Domain = "127.0.0.1"
	}

	if tc.Client == nil {
		tc.Client = &http.Client{}
	}

	uri := tc.Path
	if tc.BaseURL != "" {
		uri = tc.BaseURL + tc.Path
	}
	if strings.HasPrefix(uri, "http") {
		uri = strings.Replace(uri, "[::]", tc.Domain, 1)
		uri = strings.Replace(uri, "127.0.0.1", tc.Domain, 1)

		req, err = http.NewRequest(tc.Method, uri, ReqBodyReader(tc.Data))
		if err != nil {
			return
		}
	} else {
		req = httptest.NewRequest(tc.Method, uri, ReqBodyReader(tc.Data))
	}

	for k, v := range tc.Headers {
		req.Header.Add(k, v)
	}

	for _, c := range tc.Cookies {
		req.AddCookie(c)
	}

	formParams := url.Values{}
	for k, v := range tc.FormParams {
		formParams.Add(k, v)
	}
	req.PostForm = formParams
	req.Form = formParams

	return req, nil
}

// nopCloser is just like ioutil's, but here to let us re-read the same
// buffer inside by moving position to the start every time we done with reading
type nopCloser struct {
	io.ReadSeeker
}

// Read just a wrapper around real Read which also moves position to the start if we get EOF
// to have it ready for next read-cycle
func (n nopCloser) Read(p []byte) (int, error) {
	num, err := n.ReadSeeker.Read(p)
	if err == io.EOF { // move to start to have it ready for next read cycle
		n.Seek(0, io.SeekStart)
	}
	return num, err
}

// Close is a no-op Close
func (n nopCloser) Close() error {
	return nil
}

func copyBody(body io.ReadCloser) io.ReadCloser {
	// check if body was already read and converted into our nopCloser
	if nc, ok := body.(nopCloser); ok {
		// seek to the beginning to have it ready for next read
		nc.Seek(0, io.SeekStart)
		return body
	}

	// body is http's io.ReadCloser - let's close it after we read data
	defer body.Close()

	// body is http's io.ReadCloser - read it up until EOF
	var bodyRead bytes.Buffer
	io.Copy(&bodyRead, body)

	// use seek-able reader for further body usage
	reusableBody := bytes.NewReader(bodyRead.Bytes())

	return nopCloser{reusableBody}
}

func copyResponse(r *http.Response) *http.Response {
	if r.Body != nil {
		r.Body = copyBody(r.Body)
	}
	return r
}

type HTTPTestRunner struct {
	Do             func(*http.Request, *TestCase) (*http.Response, error)
	Assert         func(*http.Response, *TestCase) error
	RequestBuilder func(*TestCase) (*http.Request, error)
}

func (r HTTPTestRunner) Run(t testing.TB, testCases ...TestCase) (*http.Response, error) {
	var lastResponse *http.Response
	var lastError error

	if r.Do == nil {
		panic("Request runner not implemented")
	}

	if r.Assert == nil {
		r.Assert = AssertResponse
	}

	if r.RequestBuilder == nil {
		r.RequestBuilder = NewRequest
	}

	for ti, tc := range testCases {
		req, err := r.RequestBuilder(&tc)
		if err != nil {
			t.Errorf("[%d] Request build error: %s", ti, err.Error())
			continue
		}
		lastResponse, lastError = r.Do(req, &tc)
		tcJSON, _ := json.Marshal(tc)

		if lastError != nil {
			if tc.ErrorMatch != "" {
				if !strings.Contains(lastError.Error(), tc.ErrorMatch) {
					t.Errorf("[%d] Expect error `%s` to contain `%s`. %s", ti, lastError.Error(), tc.ErrorMatch, string(tcJSON))
				}
			} else {
				t.Errorf("[%d] Connection error: %s. %s", ti, lastError.Error(), string(tcJSON))
			}
			continue
		} else if tc.ErrorMatch != "" {
			t.Error("Expect error.", string(tcJSON))
			continue
		}

		respCopy := copyResponse(lastResponse)
		if lastError = r.Assert(respCopy, &tc); lastError != nil {
			t.Errorf("[%d] %s. %s\n", ti, lastError.Error(), string(tcJSON))
		}

		delay := tc.Delay

		if delay > 0 {
			time.Sleep(delay)
		}
	}

	return lastResponse, lastError
}

func HttpHandlerRunner(handler http.HandlerFunc) func(*http.Request, *TestCase) (*http.Response, error) {
	return func(r *http.Request, _ *TestCase) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler(rec, r)
		return rec.Result(), nil
	}
}

func TestHttpHandler(t testing.TB, handle http.HandlerFunc, testCases ...TestCase) {
	runner := HTTPTestRunner{
		Do: HttpHandlerRunner(handle),
	}
	runner.Run(t, testCases...)
}

func HttpServerRequestBuilder(baseURL string) func(tc *TestCase) (*http.Request, error) {
	return func(tc *TestCase) (*http.Request, error) {
		tc.BaseURL = baseURL
		return NewRequest(tc)
	}
}

func HttpServerRunner() func(*http.Request, *TestCase) (*http.Response, error) {
	return func(r *http.Request, tc *TestCase) (*http.Response, error) {
		return tc.Client.Do(r)
	}
}

func TestHttpServer(t testing.TB, baseURL string, testCases ...TestCase) {
	runner := HTTPTestRunner{
		Do:             HttpServerRunner(),
		RequestBuilder: HttpServerRequestBuilder(baseURL),
	}
	runner.Run(t, testCases...)
}
