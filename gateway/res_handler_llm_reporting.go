package gateway

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/user"
)

type LLMResponseReporterOptions struct {
}

type LLMResponseReporter struct {
	BaseTykResponseHandler
	config HeaderInjectorOptions
}

type anthropicTokenCount struct {
	Input  int `json:"input_tokens"`
	Output int `json:"output_tokens"`
}

type anthropicResponse struct {
	Usage anthropicTokenCount `json:"usage"`
}

type openAITokenCount struct {
	Input  int `json:"prompt_tokens"`
	Output int `json:"completion_tokens"`
	Total  int `json:"total_tokens"`
}

type openAIResponse struct {
	Usage openAITokenCount `json:"usage"`
}

func (h *LLMResponseReporter) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (*LLMResponseReporter) Name() string {
	return "LLMResponseReporter"
}

func (h *LLMResponseReporter) Enabled() bool {
	tagLLM := false
	for _, v := range h.Spec.Tags {
		if v == "llm" {
			tagLLM = true
		}
	}

	for _, v := range h.Spec.Tags {
		if v == "openai" || v == "anthropic" {
			if tagLLM {
				return true
			}
		}
	}

	return false
}

func (h *LLMResponseReporter) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec
	return mapstructure.Decode(c, &h.config)
}

func (h *LLMResponseReporter) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *LLMResponseReporter) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	if req.Method != http.MethodPost {
		return nil
	}
	var err error

	res.Body, err = copyBody(res.Body, false)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	for _, v := range h.Spec.Tags {
		if v == "openai" {
			var openAIResp openAIResponse
			err = json.Unmarshal(body, &openAIResp)
			if err != nil {
				return err
			}

			setCtxValue(req, ctx.LLMResponseReporterInputTokens, openAIResp.Usage.Input)
			setCtxValue(req, ctx.LLMResponseReporterOutputTokens, openAIResp.Usage.Output)
			setCtxValue(req, ctx.LLMResponseReporterTotalTokens, openAIResp.Usage.Total)

		} else if v == "anthropic" {
			var anthropicResp anthropicResponse
			err = json.Unmarshal(body, &anthropicResp)
			if err != nil {
				return err
			}

			setCtxValue(req, ctx.LLMResponseReporterInputTokens, anthropicResp.Usage.Input)
			setCtxValue(req, ctx.LLMResponseReporterOutputTokens, anthropicResp.Usage.Output)
			setCtxValue(req, ctx.LLMResponseReporterTotalTokens, anthropicResp.Usage.Input+anthropicResp.Usage.Output)
		}
	}

	return nil

}
