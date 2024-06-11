package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/pkoukk/tiktoken-go"
)

type msgObject struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type baseCompletionObject struct {
	Model    string      `json:"model"`
	Messages []msgObject `json:"messages"`
}

type LLMReport struct {
	*BaseMiddleware
}

func (sa *LLMReport) Name() string {
	return "StripAuth"
}

func (sa *LLMReport) EnabledForSpec() bool {
	for _, t := range sa.Spec.Tags {
		if strings.Contains(t, "llm") {
			if os.Getenv("TIKTOKEN_CACHE_DIR") == "" {
				sa.Logger().Warn("TIKTOKEN_CACHE_DIR is not set, LLM reporting will be slow")
			}

			return true
		}
	}

	return false
}

func (sa *LLMReport) decodeBody(r *http.Request) (*baseCompletionObject, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("Content-Type is not application/json")
	}

	var err error
	r.Body, err = copyBody(r.Body, false)
	if err != nil {
		return nil, err
	}

	bd, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var msg baseCompletionObject
	err = json.Unmarshal(bd, &msg)
	if err != nil {
		return nil, err
	}

	return &msg, nil
}

func (sa *LLMReport) detectModel(msg *baseCompletionObject) (string, bool) {
	model := "gpt-3.5-turbo"
	isEstimate := false

	if msg.Model != "" {
		model = msg.Model
	}

	_, ok := tiktoken.MODEL_TO_ENCODING[model]
	if !ok {
		model = "gpt-3.5-turbo"
		isEstimate = true
	}

	return model, isEstimate
}

func (sa *LLMReport) countTokens(msg *baseCompletionObject) (int, bool, error) {
	blob := ""
	for _, m := range msg.Messages {
		blob += m.Role
		blob += m.Content
	}

	if len(blob) == 0 {
		return 0, false, fmt.Errorf("no content to encode")
	}

	modelName, isEstimate := sa.detectModel(msg)

	tkm, err := tiktoken.EncodingForModel(modelName)
	if err != nil {
		return 0, false, err
	}

	// encode
	token := tkm.Encode(blob, nil, nil)
	return len(token), isEstimate, nil
}

func (sa *LLMReport) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if r.Method != "POST" {
		return nil, http.StatusOK
	}

	msg, err := sa.decodeBody(r)
	if err != nil {
		return err, http.StatusBadRequest
	}

	count, isEstimate, err := sa.countTokens(msg)
	if err != nil {
		return err, http.StatusBadRequest
	}

	// Pick these up in RecordHit()
	setCtxValue(r, ctx.LLMReport_Model, msg.Model)
	setCtxValue(r, ctx.LLMReport_NumRequestTokens, count)
	setCtxValue(r, ctx.LLMReport_Estimate, isEstimate)

	return nil, http.StatusOK
}
