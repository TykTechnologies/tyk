package rest_datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/httpclient"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/subscription/http_polling"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

const (
	UniqueIdentifier = "rest"
)

type Planner struct {
	client              httpclient.Client
	v                   *plan.Visitor
	config              Configuration
	rootField           int
	operationDefinition int
}

func (p *Planner) EnterOperationDefinition(ref int) {
	p.operationDefinition = ref
}

type Factory struct {
	Client httpclient.Client
}

func (f *Factory) Planner() plan.DataSourcePlanner {
	return &Planner{
		client: f.Client,
	}
}

type Configuration struct {
	Fetch        FetchConfiguration
	Subscription SubscriptionConfiguration
}

func ConfigJSON(config Configuration) json.RawMessage {
	out, _ := json.Marshal(config)
	return out
}

type SubscriptionConfiguration struct {
	PollingIntervalMillis   int64
	SkipPublishSameResponse bool
}

type FetchConfiguration struct {
	URL    string
	Method string
	Header http.Header
	Query  []QueryConfiguration
	Body   string
}

type QueryConfiguration struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (p *Planner) Register(visitor *plan.Visitor, customConfiguration json.RawMessage, isNested bool) error {
	p.v = visitor
	visitor.Walker.RegisterEnterFieldVisitor(p)
	visitor.Walker.RegisterEnterOperationVisitor(p)
	return json.Unmarshal(customConfiguration, &p.config)
}

func (p *Planner) EnterField(ref int) {
	p.rootField = ref
}

func (p *Planner) configureInput() []byte {

	input := httpclient.SetInputURL(nil, []byte(p.config.Fetch.URL))
	input = httpclient.SetInputMethod(input, []byte(p.config.Fetch.Method))
	input = httpclient.SetInputBody(input, []byte(p.config.Fetch.Body))

	header, err := json.Marshal(p.config.Fetch.Header)
	if err == nil && len(header) != 0 && !bytes.Equal(header, literal.NULL) {
		input = httpclient.SetInputHeader(input, header)
	}

	preparedQuery := p.prepareQueryParams(p.rootField, p.config.Fetch.Query)
	query, err := json.Marshal(preparedQuery)
	if err == nil && len(preparedQuery) != 0 {
		input = httpclient.SetInputQueryParams(input, query)
	}
	return input
}

func (p *Planner) ConfigureFetch() plan.FetchConfiguration {
	input := p.configureInput()
	return plan.FetchConfiguration{
		Input:     string(input),
		Variables: nil,
		DataSource: &Source{
			client: p.client,
		},
		DisallowSingleFlight: p.config.Fetch.Method != "GET",
	}
}

func (p *Planner) ConfigureSubscription() plan.SubscriptionConfiguration {

	input := p.configureInput()

	var httpPollingInput []byte
	httpPollingInput = http_polling.SetSkipPublishSameResponse(httpPollingInput, p.config.Subscription.SkipPublishSameResponse)
	httpPollingInput = http_polling.SetRequestInput(httpPollingInput, input)
	httpPollingInput = http_polling.SetInputIntervalMillis(httpPollingInput, p.config.Subscription.PollingIntervalMillis)

	return plan.SubscriptionConfiguration{
		Input:                 string(httpPollingInput),
		SubscriptionManagerID: "http_polling_stream",
		Variables:             nil,
	}
}

var (
	selectorRegex = regexp.MustCompile(`{{\s(.*?)\s}}`)
)

func (p *Planner) prepareQueryParams(field int, query []QueryConfiguration) []QueryConfiguration {
	out := make([]QueryConfiguration, 0, len(query))
Next:
	for i := range query {
		matches := selectorRegex.FindAllStringSubmatch(query[i].Value, -1)
		for j := range matches {
			if len(matches[j]) == 2 {
				path := matches[j][1]
				path = strings.TrimPrefix(path, ".")
				elements := strings.Split(path, ".")
				if len(elements) < 2 {
					continue
				}
				if elements[0] != "arguments" {
					continue
				}
				argumentName := elements[1]
				arg, ok := p.v.Operation.FieldArgument(field, []byte(argumentName))
				if !ok {
					continue Next
				}
				value := p.v.Operation.Arguments[arg].Value
				if value.Kind != ast.ValueKindVariable {
					continue Next
				}
				variableName := p.v.Operation.VariableValueNameString(value.Ref)
				if !p.v.Operation.OperationDefinitionHasVariableDefinition(p.operationDefinition, variableName) {
					continue Next
				}
			}
		}
		out = append(out, query[i])
	}
	return out
}

type Source struct {
	client httpclient.Client
}

var (
	uniqueIdentifier = []byte(UniqueIdentifier)
)

func (_ *Source) UniqueIdentifier() []byte {
	return uniqueIdentifier
}

func (s *Source) Load(ctx context.Context, input []byte, bufPair *resolve.BufPair) (err error) {
	return s.client.Do(ctx, input, bufPair.Data)
}
