package oas

type XTykPlugins struct {
	TransformHeaders     *TransformHeaders `bson:"transform-headers,omitempty" json:"transform-headers,omitempty"`
	Allowed              *Allow            `bson:"allowed,omitempty" json:"allowed,omitempty"`
	Blocked              *Allow            `bson:"blocked,omitempty" json:"blocked,omitempty"`
	IgnoreAuthentication *Allow            `bson:"ignore-authentication,omitempty" json:"ignore-authentication,omitempty"`
	Mock                 map[string]*Mock  `bson:"mock,omitempty" json:"mock,omitempty"`
}

type TransformHeaders struct {
	Request  *TransformHeader `bson:"request,omitempty" json:"request,omitempty"`
	Response *TransformHeader `bson:"response,omitempty" json:"response,omitempty"`
}

type TransformHeader struct {
	Add    map[string]string `bson:"add,omitempty" json:"add,omitempty"`
	Delete []string          `bson:"delete,omitempty" json:"delete,omitempty"`
}

type Allow struct {
	IgnoreCase bool `bson:"ignore_case" json:"ignore_case"`
}

type Mock struct {
	Data    string            `bson:"data,omitempty" json:"data,omitempty"`
	Headers map[string]string `bson:"headers,omitempty" json:"headers,omitempty"`
}
