module github.com/TykTechnologies/tyk

go 1.12

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
	github.com/TykTechnologies/tyk/certs v0.0.1
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/bshuster-repo/logrus-logstash-hook v0.4.1
	github.com/buger/jsonparser v0.0.0-20181115193947-bf1c66bbce23
	github.com/cenk/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/certifi/gocertifi v0.0.0-20190905060710-a5e0173ced67 // indirect
	github.com/clbanning/mxj v1.8.4
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/emanoelxavier/openid2go v0.0.0-20190718021401-6345b638bfc9 // indirect
	github.com/evalphobia/logrus_sentry v0.8.2
	github.com/facebookgo/clock v0.0.0-20150410010913-600d898af40a // indirect
	github.com/franela/goblin v0.0.0-20181003173013-ead4ad1d2727 // indirect
	github.com/franela/goreq v0.0.0-20171204163338-bcd34c9993f8
	github.com/gemnasium/logrus-graylog-hook v2.0.7+incompatible
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/go-redis/redis/v8 v8.3.1
	github.com/gocraft/health v0.0.0-20170925182251-8675af27fef0
	github.com/golang/protobuf v1.4.2
	github.com/google/btree v1.0.0 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/websocket v1.4.1
	github.com/hashicorp/consul/api v1.3.0
	github.com/hashicorp/go-msgpack v0.5.4 // indirect
	github.com/hashicorp/vault/api v1.0.4
	github.com/hpcloud/tail v1.0.0 // indirect
	github.com/huandu/xstrings v1.3.0 // indirect
	github.com/imdario/mergo v0.3.9 // indirect
	github.com/jensneuse/abstractlogger v0.0.4
	github.com/jensneuse/graphql-go-tools v0.0.0-00010101000000-000000000000
	github.com/justinas/alice v0.0.0-20171023064455-03f45bd4b7da
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lonelycode/go-uuid v0.0.0-20141202165402-ed3ca8a15a93
	github.com/lonelycode/osin v0.0.0-20160423095202-da239c9dacb6
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mavricknz/asn1-ber v0.0.0-20151103223136-b9df1c2f4213 // indirect
	github.com/mavricknz/ldap v0.0.0-20160227184754-f5a958005e43
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/miekg/dns v1.0.14
	github.com/mitchellh/mapstructure v1.1.2
	github.com/newrelic/go-agent v2.13.0+incompatible
	github.com/opentracing/opentracing-go v1.1.0
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/oschwald/maxminddb-golang v1.5.0
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/peterbourgon/g2s v0.0.0-20170223122336-d4e7ad98afea // indirect
	github.com/pires/go-proxyproto v0.0.0-20190615163442-2c19fd512994
	github.com/pkg/errors v0.8.1
	github.com/pmylund/go-cache v2.1.0+incompatible
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d
	github.com/rs/cors v1.7.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/square/go-jose v2.4.1+incompatible
	github.com/stretchr/testify v1.6.1
	github.com/uber-go/atomic v1.4.0 // indirect
	github.com/uber/jaeger-client-go v2.19.0+incompatible
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	github.com/valyala/fasthttp v1.15.1
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v0.0.0-20171025060643-212d8a0df7ac
	github.com/xenolf/lego v0.3.2-0.20170618175828-28ead50ff1ca // indirect
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	google.golang.org/appengine v1.6.1 // indirect
	google.golang.org/grpc v1.29.1
	gopkg.in/Masterminds/sprig.v2 v2.21.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/square/go-jose.v1 v1.1.2 // indirect
	gopkg.in/vmihailenco/msgpack.v2 v2.9.1
	gopkg.in/xmlpath.v2 v2.0.0-20150820204837-860cbeca3ebc
	gopkg.in/yaml.v2 v2.3.0
	rsc.io/letsencrypt v0.0.2
)

replace github.com/jensneuse/graphql-go-tools => github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20201012125356-562407e88c4f
