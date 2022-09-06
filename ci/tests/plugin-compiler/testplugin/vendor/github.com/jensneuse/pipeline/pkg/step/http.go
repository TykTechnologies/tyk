package step

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

type HttpStep struct {
	DefaultTimeout time.Duration `json:"default_timeout"`
	DefaultMethod  string        `json:"default_method"`
}

func UnmarshalHttpStep(reader io.Reader) (HttpStep, error) {
	var step HttpStep
	err := json.NewDecoder(reader).Decode(&step)
	return step, err
}

func NewHTTP(defaultTimeout time.Duration, defaultMethod string) HttpStep {
	return HttpStep{
		DefaultTimeout: defaultTimeout,
		DefaultMethod:  defaultMethod,
	}
}

type HttpStepInput struct {
	Timeout time.Duration          `json:"timeout"`
	Method  string                 `json:"method"`
	URL     string                 `json:"url"`
	Body    map[string]interface{} `json:"body"`
	Header  http.Header            `json:"header"`
}

type HttpStepOutput struct {
	StatusCode int                    `json:"status_code"`
	Header     http.Header            `json:"header"`
	Body       map[string]interface{} `json:"body"`
}

func (h HttpStep) Invoke(reader io.Reader, writer io.Writer) error {
	var config HttpStepInput
	err := json.NewDecoder(reader).Decode(&config)
	if err != nil {
		return err
	}

	client := h.client(config)
	req, err := h.request(config)
	if err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	var out HttpStepOutput
	out.StatusCode = res.StatusCode
	out.Header = res.Header
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &out.Body)
	if err != nil {
		return err
	}
	return json.NewEncoder(writer).Encode(out)
}

func (h *HttpStep) client(config HttpStepInput) http.Client {

	timeout := h.DefaultTimeout
	if config.Timeout != 0 {
		timeout = config.Timeout
	}

	return http.Client{
		Timeout: timeout,
	}
}

func (h *HttpStep) request(config HttpStepInput) (*http.Request, error) {
	method := h.DefaultMethod
	if config.Method != "" {
		method = config.Method
	}

	url := config.URL

	var body io.Reader
	if config.Body != nil {
		buf := &bytes.Buffer{}
		err := json.NewEncoder(buf).Encode(config.Body)
		if err != nil {
			return nil, err
		}
		body = buf
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if config.Header != nil {
		req.Header = config.Header
	}

	return req, nil
}
