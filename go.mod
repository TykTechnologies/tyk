module github.com/TykTechnologies/tyk

go 1.16

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/Jeffail/tunny v0.0.0-20171107125207-452a8e97d6a3
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/TykTechnologies/again v0.0.0-20190805133618-6ad301e7eaed
	github.com/TykTechnologies/circuitbreaker v2.2.2+incompatible
	github.com/TykTechnologies/drl v0.0.0-20190905191955-cc541aa8e3e1
	github.com/TykTechnologies/goautosocket v0.0.0-20190430121222-97bfa5e7e481
	github.com/TykTechnologies/gojsonschema v0.0.0-20170222154038-dcb3e4bb7990
	github.com/TykTechnologies/gorpc v0.0.0-20190515174534-b9c10befc5f4
	github.com/TykTechnologies/goverify v0.0.0-20160822133757-7ccc57452ade
	github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20220811124354-8d1f142966f8
	github.com/TykTechnologies/leakybucket v0.0.0-20170301023702-71692c943e3c
	github.com/TykTechnologies/murmur3 v0.0.0-20180602122059-1915e687e465
	github.com/TykTechnologies/openid2go v0.0.0-20200312160651-00c254a52b19
	github.com/TykTechnologies/tyk-pump v1.6.1-rc4
	github.com/akutz/memconn v0.1.0
	github.com/bshuster-repo/logrus-logstash-hook v0.4.1
	github.com/buger/jsonparser v1.1.1
	github.com/cenk/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/clbanning/mxj v1.8.4
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/evalphobia/logrus_sentry v0.8.2
	github.com/gemnasium/logrus-graylog-hook v2.0.7+incompatible
	github.com/getkin/kin-openapi v0.89.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gocraft/health v0.0.0-20170925182251-8675af27fef0
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/consul/api v1.3.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.4.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jensneuse/abstractlogger v0.0.4
	github.com/justinas/alice v0.0.0-20171023064455-03f45bd4b7da
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lonelycode/go-uuid v0.0.0-20141202165402-ed3ca8a15a93
	github.com/lonelycode/osin v0.0.0-20160423095202-da239c9dacb6
	github.com/mavricknz/ldap v0.0.0-20160227184754-f5a958005e43
	github.com/miekg/dns v1.0.14
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.4.1
	github.com/nats-io/nats-server/v2 v2.3.4 // indirect
	github.com/newrelic/go-agent v2.13.0+incompatible
	github.com/nsf/jsondiff v0.0.0-20210303162244-6ea32392771e
	github.com/opentracing/opentracing-go v1.2.0
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/oschwald/maxminddb-golang v1.5.0
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/pires/go-proxyproto v0.0.0-20190615163442-2c19fd512994
	github.com/pmylund/go-cache v2.1.0+incompatible
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d
	github.com/rs/cors v1.7.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/afero v1.6.0
	github.com/square/go-jose v2.4.1+incompatible
	github.com/stretchr/testify v1.7.0
	github.com/uber/jaeger-client-go v2.20.0+incompatible
	github.com/valyala/fasthttp v1.15.1
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/grpc v1.36.0
	google.golang.org/grpc/examples v0.0.0-20220317213542-f95b001a48df
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/vmihailenco/msgpack.v2 v2.9.1
	gopkg.in/xmlpath.v2 v2.0.0-20150820204837-860cbeca3ebc
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	rsc.io/letsencrypt v0.0.2
)

replace gorm.io/gorm => github.com/TykTechnologies/gorm v1.20.7-0.20210409171139-b5c340f85ed0

//replace github.com/TykTechnologies/graphql-go-tools => ../graphql-go-tools
