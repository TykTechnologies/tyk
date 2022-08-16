package apidef

type InboundData struct {
	KeyName      string
	Value        string
	SessionState string
	Timeout      int64
	Per          int64
	Expire       int64
}

type DefRequest struct {
	OrgId   string
	Tags    []string
	LoadOAS bool
}

type GroupLoginRequest struct {
	UserKey string
	GroupID string
}

type GroupKeySpaceRequest struct {
	OrgID   string
	GroupID string
}

type KeysValuesPair struct {
	Keys   []string
	Values []string
}
