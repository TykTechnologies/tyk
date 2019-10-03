package internal

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/newrelic/go-agent/internal/logger"
)

const (
	lambdaMetadataVersion = 2

	// AgentLanguage is used in the connect JSON and the Lambda JSON.
	AgentLanguage = "go"
)

// ServerlessHarvest is used to store and log data when the agent is running in
// serverless mode.
type ServerlessHarvest struct {
	logger          logger.Logger
	version         string
	awsExecutionEnv string

	// The Lambda handler could be using multiple goroutines so we use a
	// mutex to prevent race conditions.
	sync.Mutex
	harvest *Harvest
}

// NewServerlessHarvest creates a new ServerlessHarvest.
func NewServerlessHarvest(logger logger.Logger, version string, getEnv func(string) string) *ServerlessHarvest {
	return &ServerlessHarvest{
		logger:          logger,
		version:         version,
		awsExecutionEnv: getEnv("AWS_EXECUTION_ENV"),

		// A ConnectReply parameter to NewHarvest isn't needed because
		// serverless mode doesn't have a connect, and therefore won't
		// have custom event limits from the server.
		harvest: NewHarvest(time.Now(), nil),
	}
}

// Consume adds data to the harvest.
func (sh *ServerlessHarvest) Consume(data Harvestable) {
	if nil == sh {
		return
	}
	sh.Lock()
	defer sh.Unlock()

	data.MergeIntoHarvest(sh.harvest)
}

func (sh *ServerlessHarvest) swapHarvest() *Harvest {
	sh.Lock()
	defer sh.Unlock()

	h := sh.harvest
	sh.harvest = NewHarvest(time.Now(), nil)
	return h
}

// Write logs the data in the format described by:
// https://source.datanerd.us/agents/agent-specs/blob/master/Lambda.md
func (sh *ServerlessHarvest) Write(arn string, writer io.Writer) {
	if nil == sh {
		return
	}
	harvest := sh.swapHarvest()
	payloads := harvest.Payloads(false)
	// Note that *json.RawMessage (instead of json.RawMessage) is used to
	// support older Go versions: https://go-review.googlesource.com/c/go/+/21811/
	harvestPayloads := make(map[string]*json.RawMessage, len(payloads))
	for _, p := range payloads {
		agentRunID := ""
		cmd := p.EndpointMethod()
		data, err := p.Data(agentRunID, time.Now())
		if err != nil {
			sh.logger.Error("error creating payload json", map[string]interface{}{
				"command": cmd,
				"error":   err.Error(),
			})
			continue
		}
		if nil == data {
			continue
		}
		// NOTE!  This code relies on the fact that each payload is
		// using a different endpoint method.  Sometimes the transaction
		// events payload might be split, but since there is only one
		// transaction event per serverless transaction, that's not an
		// issue.  Likewise, if we ever split normal transaction events
		// apart from synthetics events, the transaction will either be
		// normal or synthetic, so that won't be an issue.  Log an error
		// if this happens for future defensiveness.
		if _, ok := harvestPayloads[cmd]; ok {
			sh.logger.Error("data with duplicate command name lost", map[string]interface{}{
				"command": cmd,
			})
		}
		d := json.RawMessage(data)
		harvestPayloads[cmd] = &d
	}

	if len(harvestPayloads) == 0 {
		// The harvest may not contain any data if the serverless
		// transaction was ignored.
		return
	}

	data, err := json.Marshal(harvestPayloads)
	if nil != err {
		sh.logger.Error("error creating serverless data json", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	var dataBuf bytes.Buffer
	gz := gzip.NewWriter(&dataBuf)
	gz.Write(data)
	gz.Flush()
	gz.Close()

	js, err := json.Marshal([]interface{}{
		lambdaMetadataVersion,
		"NR_LAMBDA_MONITORING",
		struct {
			MetadataVersion      int    `json:"metadata_version"`
			ARN                  string `json:"arn,omitempty"`
			ProtocolVersion      int    `json:"protocol_version"`
			ExecutionEnvironment string `json:"execution_environment,omitempty"`
			AgentVersion         string `json:"agent_version"`
			AgentLanguage        string `json:"agent_language"`
		}{
			MetadataVersion:      lambdaMetadataVersion,
			ProtocolVersion:      ProcotolVersion,
			AgentVersion:         sh.version,
			ExecutionEnvironment: sh.awsExecutionEnv,
			ARN:                  arn,
			AgentLanguage:        AgentLanguage,
		},
		base64.StdEncoding.EncodeToString(dataBuf.Bytes()),
	})

	if err != nil {
		sh.logger.Error("error creating serverless json", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	fmt.Fprintln(writer, string(js))
}

// ParseServerlessPayload exists for testing.
func ParseServerlessPayload(data []byte) (metadata, uncompressedData map[string]json.RawMessage, err error) {
	var arr [4]json.RawMessage
	if err = json.Unmarshal(data, &arr); nil != err {
		err = fmt.Errorf("unable to unmarshal serverless data array: %v", err)
		return
	}
	var dataJSON []byte
	compressed := strings.Trim(string(arr[3]), `"`)
	if dataJSON, err = decodeUncompress(compressed); nil != err {
		err = fmt.Errorf("unable to uncompress serverless data: %v", err)
		return
	}
	if err = json.Unmarshal(dataJSON, &uncompressedData); nil != err {
		err = fmt.Errorf("unable to unmarshal uncompressed serverless data: %v", err)
		return
	}
	if err = json.Unmarshal(arr[2], &metadata); nil != err {
		err = fmt.Errorf("unable to unmarshal serverless metadata: %v", err)
		return
	}
	return
}

func decodeUncompress(input string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if nil != err {
		return nil, err
	}

	buf := bytes.NewBuffer(decoded)
	gz, err := gzip.NewReader(buf)
	if nil != err {
		return nil, err
	}
	var out bytes.Buffer
	io.Copy(&out, gz)
	gz.Close()

	return out.Bytes(), nil
}

// ServerlessWriter is implemented by newrelic.Application.
type ServerlessWriter interface {
	ServerlessWrite(arn string, writer io.Writer)
}

// ServerlessWrite exists to avoid type assertion in the nrlambda integration
// package.
func ServerlessWrite(app interface{}, arn string, writer io.Writer) {
	if s, ok := app.(ServerlessWriter); ok {
		s.ServerlessWrite(arn, writer)
	}
}
