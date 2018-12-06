package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type TestCase struct {
	Method, Path    string            `json:",omitempty"`
	Domain          string            `json:",omitempty"`
	Code            int               `json:",omitempty"`
	Data            interface{}       `json:",omitempty"`
	Headers         map[string]string `json:",omitempty"`
	PathParams      map[string]string `json:",omitempty"`
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

func AssertResponse(resp *http.Response, tc TestCase) error {
	body, _ := ioutil.ReadAll(resp.Body)
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

func reqBodyReader(body interface{}) io.Reader {
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

func NewRequest(tc TestCase) (req *http.Request) {
	if tc.Method == "" {
		tc.Method = "GET"
	}

	req, _ = http.NewRequest(tc.Method, tc.Path, reqBodyReader(tc.Data))

	for k, v := range tc.Headers {
		req.Header.Add(k, v)
	}

	for _, c := range tc.Cookies {
		req.AddCookie(c)
	}

	return req
}
