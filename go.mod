module github.com/TykTechnologies/tyk

go 1.15

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
	github.com/TykTechnologies/goverify v0.0.0-20220808203004-1486f89e7708
	github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20230412132247-218da3d7039e
	github.com/TykTechnologies/leakybucket v0.0.0-20170301023702-71692c943e3c
	github.com/TykTechnologies/murmur3 v0.0.0-20180602122059-1915e687e465
	github.com/TykTechnologies/openid2go v0.0.0-20200312160651-00c254a52b19
	github.com/akutz/memconn v0.1.0
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/armon/go-metrics v0.3.10 // indirect
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
	github.com/frankban/quicktest v1.11.0 // indirect
	github.com/gemnasium/logrus-graylog-hook v2.0.7+incompatible
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/go-redis/redis/v8 v8.3.1
	github.com/gocraft/health v0.0.0-20170925182251-8675af27fef0
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/golang/protobuf v1.4.2
	github.com/google/btree v1.0.0 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/consul/api v1.3.0
	github.com/hashicorp/consul/sdk v0.8.0 // indirect
	github.com/hashicorp/go-hclog v0.14.1 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.0 // indirect
	github.com/hashicorp/go-msgpack v0.5.5 // indirect
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/go-retryablehttp v0.6.7 // indirect
	github.com/hashicorp/go-version v1.1.0
	github.com/hashicorp/memberlist v0.1.6 // indirect
	github.com/hashicorp/serf v0.8.6 // indirect
	github.com/hashicorp/vault/api v1.0.5-0.20200717191844-f687267c8086
	github.com/jensneuse/abstractlogger v0.0.4
	github.com/justinas/alice v0.0.0-20171023064455-03f45bd4b7da
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lonelycode/go-uuid v0.0.0-20141202165402-ed3ca8a15a93 // indirect
	github.com/lonelycode/osin v0.0.0-20160423095202-da239c9dacb6
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mavricknz/asn1-ber v0.0.0-20151103223136-b9df1c2f4213 // indirect
	github.com/mavricknz/ldap v0.0.0-20160227184754-f5a958005e43
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/miekg/dns v1.0.14
	github.com/mitchellh/go-testing-interface v1.14.0 // indirect
	github.com/mitchellh/mapstructure v1.4.1
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/nats-io/nats-server/v2 v2.3.4 // indirect
	github.com/newrelic/go-agent v2.13.0+incompatible
	github.com/nsf/jsondiff v0.0.0-20210303162244-6ea32392771e
	github.com/opentracing/opentracing-go v1.1.0
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/oschwald/maxminddb-golang v1.5.0
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/peterbourgon/g2s v0.0.0-20170223122336-d4e7ad98afea // indirect
	github.com/pierrec/lz4 v2.5.2+incompatible // indirect
	github.com/pires/go-proxyproto v0.0.0-20190615163442-2c19fd512994
	github.com/pkg/errors v0.9.1
	github.com/pmylund/go-cache v2.1.0+incompatible
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d
	github.com/rs/cors v1.7.0
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
	golang.org/x/net v0.0.0-20211209124913-491a49abca63
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20211013075003-97ac67df715c // indirect
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	google.golang.org/appengine v1.6.1 // indirect
	google.golang.org/grpc v1.29.1
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

<<<<<<< HEAD
//replace github.com/jensneuse/graphql-go-tools => ../graphql-go-tools
replace sourcegraph.com/sourcegraph/appdash => github.com/sourcegraph/appdash v0.0.0-20211028080628-e2786a622600
=======
require (
	github.com/Jeffail/gabs/v2 v2.7.0
	github.com/TykTechnologies/kin-openapi v0.90.0
	github.com/TykTechnologies/opentelemetry v0.0.20
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/go-redis/redismock/v8 v8.11.5
	github.com/google/go-cmp v0.6.0
	github.com/newrelic/go-agent v2.13.0+incompatible
	go.opentelemetry.io/otel v1.19.0
	go.opentelemetry.io/otel/trace v1.19.0
	go.uber.org/mock v0.3.0
)

require (
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/IBM/sarama v1.42.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/asyncapi/converter-go v0.0.0-20190802111537-d8459b2bd403 // indirect
	github.com/asyncapi/parser-go v0.4.2 // indirect
	github.com/asyncapi/spec-json-schemas/v2 v2.14.0 // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/certifi/gocertifi v0.0.0-20210507211836-431795d63e8d // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/eapache/go-resiliency v1.4.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/eclipse/paho.mqtt.golang v1.2.0 // indirect
	github.com/facebookgo/clock v0.0.0-20150410010913-600d898af40a // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-logr/logr v1.3.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/gobwas/httphead v0.0.0-20180130184737-2c6c146eadee // indirect
	github.com/gobwas/pool v0.2.0 // indirect
	github.com/gobwas/ws v1.0.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.5.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.6 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/serf v0.10.1 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/iancoleman/strcase v0.2.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/invopop/yaml v0.2.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jensneuse/byte-template v0.0.0-20200214152254-4f3cf06e5c68 // indirect
	github.com/jensneuse/pipeline v0.0.0-20200117120358-9fb4de085cd6 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.2 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.17.0 // indirect
	github.com/lonelycode/go-uuid v0.0.0-20141202165402-ed3ca8a15a93 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mavricknz/asn1-ber v0.0.0-20151103223136-b9df1c2f4213 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/perimeterx/marshmallow v1.1.5 // indirect
	github.com/peterbourgon/g2s v0.0.0-20170223122336-d4e7ad98afea // indirect
	github.com/pierrec/lz4/v4 v4.1.18 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/pvormste/websocket v1.8.8 // indirect
	github.com/r3labs/sse/v2 v2.8.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/tidwall/gjson v1.11.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.0.4 // indirect
	github.com/uber/jaeger-lib v2.4.2-0.20210604143007-135cf5605a6d+incompatible // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190809123943-df4f5c81cb3b // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.45.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.17.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.18.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.18.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.18.0 // indirect
	go.opentelemetry.io/otel/metric v1.19.0 // indirect
	go.opentelemetry.io/otel/sdk v1.18.0 // indirect
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.18.1 // indirect
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.13.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231120223509-83a465c0220f // indirect
	gopkg.in/cenkalti/backoff.v1 v1.1.0 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gorm.io/gorm v1.21.16 // indirect
)
>>>>>>> ee5dc29b... [TT-10826] self trim oAuth sorted set (#5907)

replace sourcegraph.com/sourcegraph/appdash-data => github.com/sourcegraph/appdash-data v0.0.0-20151005221446-73f23eafcf67
