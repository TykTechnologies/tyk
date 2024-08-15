package rpc

type GRPCConnectionHandler struct{}

func (g *GRPCConnectionHandler) Connect(_ Config, _ bool, _ map[string]interface{}, _ func(string, string) interface{}, _ func(), _ func()) bool {
	return true
}

func (g *GRPCConnectionHandler) Disconnect() bool {
	return true
}

func (g *GRPCConnectionHandler) FuncClientSingleton(_ string, _ interface{}) (interface{}, error) {
	return nil, nil
}

func (g *GRPCConnectionHandler) Login() bool {
	return true
}

func (g *GRPCConnectionHandler) GroupLogin() bool {
	return true
}

func (g *GRPCConnectionHandler) LoadCount() int {
	return 0
}

func (g *GRPCConnectionHandler) Reset() {
}

func (g *GRPCConnectionHandler) EmitErrorEvent(_ string, _ string, _ error) {
	// no op
}

func (g *GRPCConnectionHandler) EmitErrorEventKv(_ string, _ string, _ error, _ map[string]string) {
	// no op
}

func (g *GRPCConnectionHandler) CloseConnections() {
	// no op
}
