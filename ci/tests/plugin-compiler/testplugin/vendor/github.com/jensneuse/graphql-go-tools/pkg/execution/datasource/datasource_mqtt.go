package datasource

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	log "github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type MQTTDataSourceConfig struct {
	BrokerAddr string
	ClientID   string
	Topic      string
}

type MQTTDataSourcePlannerFactoryFactory struct {
}

func (M MQTTDataSourcePlannerFactoryFactory) Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error) {
	factory := &MQTTDataSourcePlannerFactory{
		base: base,
	}
	return factory, json.NewDecoder(configReader).Decode(&factory.config)
}

type MQTTDataSourcePlannerFactory struct {
	base   BasePlanner
	config MQTTDataSourceConfig
}

func (m MQTTDataSourcePlannerFactory) DataSourcePlanner() Planner {
	return &MQTTDataSourcePlanner{
		BasePlanner:      m.base,
		dataSourceConfig: m.config,
	}
}

type MQTTDataSourcePlanner struct {
	BasePlanner
	dataSourceConfig MQTTDataSourceConfig
}

func (n *MQTTDataSourcePlanner) Plan(args []Argument) (DataSource, []Argument) {
	return &MQTTDataSource{
		log: n.Log,
	}, append(n.Args, args...)
}

func (n *MQTTDataSourcePlanner) EnterDocument(operation, definition *ast.Document) {

}

func (n *MQTTDataSourcePlanner) EnterInlineFragment(ref int) {

}

func (n *MQTTDataSourcePlanner) LeaveInlineFragment(ref int) {

}

func (n *MQTTDataSourcePlanner) EnterSelectionSet(ref int) {

}

func (n *MQTTDataSourcePlanner) LeaveSelectionSet(ref int) {

}

func (n *MQTTDataSourcePlanner) EnterField(ref int) {
	n.RootField.SetIfNotDefined(ref)
}

func (n *MQTTDataSourcePlanner) EnterArgument(ref int) {

}

func (n *MQTTDataSourcePlanner) LeaveField(ref int) {
	if !n.RootField.IsDefinedAndEquals(ref) {
		return
	}
	n.Args = append(n.Args, &StaticVariableArgument{
		Name:  literal.BROKERADDR,
		Value: []byte(n.dataSourceConfig.BrokerAddr),
	})
	n.Args = append(n.Args, &StaticVariableArgument{
		Name:  literal.CLIENTID,
		Value: []byte(n.dataSourceConfig.ClientID),
	})
	n.Args = append(n.Args, &StaticVariableArgument{
		Name:  literal.TOPIC,
		Value: []byte(n.dataSourceConfig.Topic),
	})
}

type MQTTDataSource struct {
	log    log.Logger
	once   sync.Once
	ch     chan mqtt.Message
	client mqtt.Client
}

func (m *MQTTDataSource) Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error) {

	defer func() {
		select {
		case <-ctx.Done():
			m.log.Debug("MQTTDataSource.Resolve.client.Disconnect")
			m.client.Disconnect(250)
			m.log.Debug("MQTTDataSource.Resolve.client.Disconnect.disconnected")
		default:
			return
		}
	}()

	m.once.Do(func() {

		brokerArg := args.ByKey(literal.BROKERADDR)
		clientIDArg := args.ByKey(literal.CLIENTID)
		topicArg := args.ByKey(literal.TOPIC)

		m.log.Debug("MQTTDataSource.Resolve.init",
			log.String("broker", string(brokerArg)),
			log.String("clientID", string(clientIDArg)),
			log.String("topic", string(topicArg)),
		)

		m.ch = make(chan mqtt.Message)
		m.start(string(brokerArg), string(clientIDArg), string(topicArg))
	})

	select {
	case <-ctx.Done():
		return
	case msg, ok := <-m.ch:
		if !ok {
			return
		}
		return out.Write(msg.Payload())
	}
}

func (m *MQTTDataSource) start(brokerAddr, clientID, topic string) {
	mqtt.ERROR = m.log.LevelLogger(log.ErrorLevel)
	mqtt.DEBUG = m.log.LevelLogger(log.DebugLevel)
	opts := mqtt.NewClientOptions().AddBroker(brokerAddr).SetClientID(clientID)
	opts.SetKeepAlive(5 * time.Second)
	opts.SetResumeSubs(true)
	opts.SetAutoReconnect(true)
	opts.SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
		m.ch <- msg
		msg.Ack()
	})
	opts.SetPingTimeout(5 * time.Second)

	m.client = mqtt.NewClient(opts)
	if token := m.client.Connect(); token.Wait() && token.Error() != nil {
		m.log.Error("MQTTDataSource.start.Connect",
			log.Error(token.Error()),
		)
		close(m.ch)
		return
	}

	if token := m.client.Subscribe(topic, 0, nil); token.Wait() && token.Error() != nil {
		m.log.Error("MQTTDataSource.start.Subscribe",
			log.Error(token.Error()),
		)
		close(m.ch)
		return
	}
}
