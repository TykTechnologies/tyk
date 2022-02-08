module github.com/TykTechnologies/tyk

go 1.15

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/Jeffail/tunny v0.0.0-20171107125207-452a8e97d6a3
	github.com/TykTechnologies/again v0.0.0-20190805133618-6ad301e7eaed
	github.com/TykTechnologies/circuitbreaker v2.2.2+incompatible
	github.com/TykTechnologies/drl v0.0.0-20190905191955-cc541aa8e3e1
	github.com/TykTechnologies/goautosocket v0.0.0-20190430121222-97bfa5e7e481
	github.com/TykTechnologies/gojsonschema v0.0.0-20170222154038-dcb3e4bb7990
	github.com/TykTechnologies/gorpc v0.0.0-20190515174534-b9c10befc5f4
	github.com/TykTechnologies/goverify v0.0.0-20160822133757-7ccc57452ade
	github.com/TykTechnologies/leakybucket v0.0.0-20170301023702-71692c943e3c
	github.com/TykTechnologies/murmur3 v0.0.0-20180602122059-1915e687e465
	github.com/TykTechnologies/openid2go v0.0.0-20200312160651-00c254a52b19
	github.com/akutz/memconn v0.1.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/bshuster-repo/logrus-logstash-hook v0.4.1
	github.com/buger/jsonparser v1.1.1
	github.com/cenk/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/certifi/gocertifi v0.0.0-20190905060710-a5e0173ced67 // indirect
	github.com/clbanning/mxj v1.8.4
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/emanoelxavier/openid2go v0.0.0-20190718021401-6345b638bfc9 // indirect
	github.com/evalphobia/logrus_sentry v0.8.2
	github.com/facebookgo/clock v0.0.0-20150410010913-600d898af40a // indirect
	github.com/gemnasium/logrus-graylog-hook v2.0.7+incompatible
	github.com/getkin/kin-openapi v0.32.0
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/go-redis/redis/v8 v8.3.1
	github.com/gocraft/health v0.0.0-20170925182251-8675af27fef0
	github.com/golang/protobuf v1.4.2
	github.com/google/btree v1.0.0 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/consul/api v1.3.0
	github.com/hashicorp/go-msgpack v0.5.4 // indirect
	github.com/hashicorp/vault/api v1.0.4
	github.com/huandu/xstrings v1.3.0 // indirect
	github.com/imdario/mergo v0.3.9 // indirect
	github.com/jensneuse/abstractlogger v0.0.4
	github.com/jensneuse/graphql-go-tools v1.20.2
	github.com/jensneuse/graphql-go-tools/examples/federation v0.0.0-20210804084050-3c2e37945919 // indirect
	github.com/justinas/alice v0.0.0-20171023064455-03f45bd4b7da
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lonelycode/go-uuid v0.0.0-20141202165402-ed3ca8a15a93
	github.com/lonelycode/osin v0.0.0-20160423095202-da239c9dacb6
	github.com/mavricknz/asn1-ber v0.0.0-20151103223136-b9df1c2f4213 // indirect
	github.com/mavricknz/ldap v0.0.0-20160227184754-f5a958005e43
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/miekg/dns v1.0.14
	github.com/mitchellh/mapstructure v1.4.1
	github.com/nats-io/nats-server/v2 v2.3.4 // indirect
	github.com/newrelic/go-agent v2.13.0+incompatible
	github.com/nsf/jsondiff v0.0.0-20210303162244-6ea32392771e
	github.com/opentracing/opentracing-go v1.1.0
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/oschwald/maxminddb-golang v1.5.0
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/peterbourgon/g2s v0.0.0-20170223122336-d4e7ad98afea // indirect
	github.com/pires/go-proxyproto v0.0.0-20190615163442-2c19fd512994
	github.com/pkg/errors v0.9.1
	github.com/pmylund/go-cache v2.1.0+incompatible
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d
	github.com/rs/cors v1.7.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.6.0
	github.com/square/go-jose v2.4.1+incompatible
	github.com/stretchr/testify v1.7.0
	github.com/uber-go/atomic v1.4.0 // indirect
	github.com/uber/jaeger-client-go v2.19.0+incompatible
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	github.com/valyala/fasthttp v1.15.1
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	github.com/xeipuuv/gojsonschema v1.2.0
	github.com/xenolf/lego v0.3.2-0.20170618175828-28ead50ff1ca // indirect
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9
	google.golang.org/appengine v1.6.1 // indirect
	google.golang.org/grpc v1.29.1
	gopkg.in/Masterminds/sprig.v2 v2.21.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/sourcemap.v1 v1.0.5 // indirect; indi    rect
	gopkg.in/square/go-jose.v1 v1.1.2 // indirect
	gopkg.in/vmihailenco/msgpack.v2 v2.9.1
	gopkg.in/xmlpath.v2 v2.0.0-20150820204837-860cbeca3ebc
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	gorm.io/gorm v1.21.11
	rsc.io/letsencrypt v0.0.2
)

replace github.com/jensneuse/graphql-go-tools => github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20220203135520-f818861b88dc

//replace github.com/jensneuse/graphql-go-tools => ../graphql-go-tools
