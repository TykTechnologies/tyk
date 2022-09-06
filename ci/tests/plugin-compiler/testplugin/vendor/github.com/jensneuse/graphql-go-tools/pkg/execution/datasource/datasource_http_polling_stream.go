package datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	log "github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type HttpPollingStreamDataSourceConfiguration struct {
	Host         string
	URL          string
	DelaySeconds *int
}

type HttpPollingStreamDataSourcePlannerFactoryFactory struct {
}

func (h HttpPollingStreamDataSourcePlannerFactoryFactory) Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error) {
	factory := &HttpPollingStreamDataSourcePlannerFactory{
		base: base,
	}
	return factory, json.NewDecoder(configReader).Decode(&factory.config)
}

type HttpPollingStreamDataSourcePlannerFactory struct {
	base   BasePlanner
	config HttpPollingStreamDataSourceConfiguration
}

func (h HttpPollingStreamDataSourcePlannerFactory) DataSourcePlanner() Planner {
	return &HttpPollingStreamDataSourcePlanner{
		BasePlanner:      h.base,
		dataSourceConfig: h.config,
	}
}

type HttpPollingStreamDataSourcePlanner struct {
	BasePlanner
	dataSourceConfig HttpPollingStreamDataSourceConfiguration
	delay            time.Duration
}

func (h *HttpPollingStreamDataSourcePlanner) Plan(args []Argument) (DataSource, []Argument) {
	return &HttpPollingStreamDataSource{
		Log:   h.Log,
		Delay: h.delay,
	}, append(h.Args, args...)
}

func (h *HttpPollingStreamDataSourcePlanner) EnterDocument(operation, definition *ast.Document) {

}

func (h *HttpPollingStreamDataSourcePlanner) EnterInlineFragment(ref int) {

}

func (h *HttpPollingStreamDataSourcePlanner) LeaveInlineFragment(ref int) {

}

func (h *HttpPollingStreamDataSourcePlanner) EnterSelectionSet(ref int) {

}

func (h *HttpPollingStreamDataSourcePlanner) LeaveSelectionSet(ref int) {

}

func (h *HttpPollingStreamDataSourcePlanner) EnterField(ref int) {
	h.RootField.SetIfNotDefined(ref)
}

func (h *HttpPollingStreamDataSourcePlanner) EnterArgument(ref int) {

}

func (h *HttpPollingStreamDataSourcePlanner) LeaveField(ref int) {
	if !h.RootField.IsDefinedAndEquals(ref) {
		return
	}
	h.Args = append(h.Args, &StaticVariableArgument{
		Name:  literal.HOST,
		Value: []byte(h.dataSourceConfig.Host),
	})
	h.Args = append(h.Args, &StaticVariableArgument{
		Name:  literal.URL,
		Value: []byte(h.dataSourceConfig.URL),
	})
	if h.dataSourceConfig.DelaySeconds == nil {
		h.delay = time.Second * time.Duration(1)
	} else {
		h.delay = time.Second * time.Duration(*h.dataSourceConfig.DelaySeconds)
	}
}

type HttpPollingStreamDataSource struct {
	Log      log.Logger
	once     sync.Once
	ch       chan []byte
	closed   bool
	Delay    time.Duration
	client   *http.Client
	request  *http.Request
	lastData []byte
}

func (h *HttpPollingStreamDataSource) Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error) {
	h.once.Do(func() {
		h.ch = make(chan []byte)
		h.request = h.generateRequest(args)
		h.client = &http.Client{
			Timeout: time.Second * 5,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 1024,
				TLSHandshakeTimeout: 0 * time.Second,
			},
		}
		go h.startPolling(ctx)
	})
	if h.closed {
		return
	}
	select {
	case data := <-h.ch:
		h.Log.Debug("HttpPollingStreamDataSource.Resolve.out.Write",
			log.ByteString("data", data),
		)
		_, err := out.Write(data)
		if err != nil {
			h.Log.Error("HttpPollingStreamDataSource.Resolve",
				log.Error(err),
			)
		}
	case <-ctx.Done():
		h.closed = true
		return
	}
	return
}

func (h *HttpPollingStreamDataSource) startPolling(ctx context.Context) {
	first := true
	for {
		if first {
			first = !first
		} else {
			time.Sleep(h.Delay)
		}
		var data []byte
		select {
		case <-ctx.Done():
			h.closed = true
			return
		default:
			response, err := h.client.Do(h.request)
			if err != nil {
				h.Log.Error("HttpPollingStreamDataSource.startPolling.client.Do",
					log.Error(err),
				)
				return
			}
			data, err = ioutil.ReadAll(response.Body)
			if err != nil {
				h.Log.Error("HttpPollingStreamDataSource.startPolling.ioutil.ReadAll",
					log.Error(err),
				)
				return
			}
		}
		if bytes.Equal(data, h.lastData) {
			continue
		}
		h.lastData = data
		select {
		case <-ctx.Done():
			h.closed = true
			return
		case h.ch <- data:
			continue
		}
	}
}

func (h *HttpPollingStreamDataSource) generateRequest(args ResolverArgs) *http.Request {
	hostArg := args.ByKey(literal.HOST)
	urlArg := args.ByKey(literal.URL)

	h.Log.Debug("HttpPollingStreamDataSource.generateRequest.Resolve.Args",
		log.Strings("resolvedArgs", args.Dump()),
	)

	if hostArg == nil || urlArg == nil {
		h.Log.Error("HttpPollingStreamDataSource.generateRequest.Args invalid")
		return nil
	}

	url := string(hostArg) + string(urlArg)
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		url = "https://" + url
	}

	if strings.Contains(url, "{{") {
		tmpl, err := template.New("url").Parse(url)
		if err != nil {
			h.Log.Error("HttpPollingStreamDataSource.generateRequest.template.New",
				log.Error(err),
			)
			return nil
		}
		out := bytes.Buffer{}
		keys := args.Keys()
		data := make(map[string]string, len(keys))
		for i := 0; i < len(keys); i++ {
			data[string(keys[i])] = string(args.ByKey(keys[i]))
		}
		err = tmpl.Execute(&out, data)
		if err != nil {
			h.Log.Error("HttpPollingStreamDataSource.generateRequest.tmpl.Execute",
				log.Error(err),
			)
			return nil
		}
		url = out.String()
	}

	h.Log.Debug("HttpPollingStreamDataSource.generateRequest.Resolve",
		log.String("url", url),
	)

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		h.Log.Error("HttpPollingStreamDataSource.generateRequest.Resolve.NewRequest",
			log.Error(err),
		)
		return nil
	}
	request.Header.Add("Accept", "application/json")
	return request
}
