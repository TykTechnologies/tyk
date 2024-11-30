module github.com/TykTechnologies/tyk

go 1.22.6

require (
	github.com/Jeffail/tunny v0.1.4
	github.com/Masterminds/sprig/v3 v3.3.0
	github.com/TykTechnologies/again v0.0.0-20190805133618-6ad301e7eaed
	github.com/TykTechnologies/circuitbreaker v2.2.2+incompatible
	github.com/TykTechnologies/drl v0.0.0-20231218155806-88e4363884a2
	github.com/TykTechnologies/goautosocket v0.0.0-20190430121222-97bfa5e7e481
	github.com/TykTechnologies/gojsonschema v0.0.0-20170222154038-dcb3e4bb7990
	github.com/TykTechnologies/gorpc v0.0.0-20241016124253-606484472fbb
	github.com/TykTechnologies/goverify v0.0.0-20220808203004-1486f89e7708
	github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20240926103032-6eca9f4b5e30
	github.com/TykTechnologies/graphql-translator v0.0.0-20240319092712-4ba87e4c06ff
	github.com/TykTechnologies/leakybucket v0.0.0-20170301023702-71692c943e3c
	github.com/TykTechnologies/murmur3 v0.0.0-20230310161213-aad17efd5632
	github.com/TykTechnologies/openid2go v0.1.2
	github.com/TykTechnologies/storage v1.2.2
	github.com/TykTechnologies/tyk-pump v1.10.0
	github.com/akutz/memconn v0.1.0
	github.com/bshuster-repo/logrus-logstash-hook v1.1.0
	github.com/buger/jsonparser v1.1.1
	github.com/cenk/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/clbanning/mxj v1.8.4
	github.com/evalphobia/logrus_sentry v0.8.2
	github.com/gemnasium/logrus-graylog-hook v2.0.7+incompatible
	github.com/getkin/kin-openapi v0.115.0
	github.com/go-jose/go-jose/v3 v3.0.3
	github.com/gocraft/health v0.0.0-20170925182251-8675af27fef0
	github.com/gofrs/uuid v4.4.0+incompatible
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/consul/api v1.30.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.7.0
	github.com/hashicorp/vault/api v1.15.0
	github.com/jensneuse/abstractlogger v0.0.4
	github.com/justinas/alice v1.2.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lonelycode/osin v0.0.0-20160423095202-da239c9dacb6
	github.com/mavricknz/ldap v0.0.0-20160227184754-f5a958005e43
	github.com/miekg/dns v1.1.62
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0
	github.com/nsf/jsondiff v0.0.0-20230430225905-43f6cf3098c1 // test
	github.com/opentracing/opentracing-go v1.2.0
	github.com/openzipkin/zipkin-go v0.4.3
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/pires/go-proxyproto v0.7.0
	github.com/pmylund/go-cache v2.1.0+incompatible
	github.com/robertkrimen/otto v0.4.0
	github.com/rs/cors v1.11.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.11.0
	github.com/stretchr/testify v1.9.0 // test
	github.com/uber/jaeger-client-go v2.30.1-0.20220110192849-8d8e8fcfd04d+incompatible
	github.com/valyala/fasthttp v1.55.0 // test
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.27.0
	golang.org/x/net v0.29.0
	golang.org/x/sync v0.8.0
	google.golang.org/grpc v1.66.2
	google.golang.org/grpc/examples v0.0.0-20220317213542-f95b001a48df // test
	google.golang.org/protobuf v1.34.2
	gopkg.in/vmihailenco/msgpack.v2 v2.9.2
	gopkg.in/xmlpath.v2 v2.0.0-20150820204837-860cbeca3ebc
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/TykTechnologies/exp/pkg/limiters v0.0.0-20231219151617-0c4f9315fe5c
	github.com/go-redsync/redsync/v4 v4.13.0
	github.com/redis/go-redis/v9 v9.6.1
)

require (
	github.com/IBM/sarama v1.43.1
	github.com/Jeffail/gabs/v2 v2.7.0
	github.com/TykTechnologies/graphql-go-tools/v2 v2.0.0-20240509085643-e95cdc317e1d
	github.com/TykTechnologies/kin-openapi v0.90.0
	github.com/TykTechnologies/opentelemetry v0.0.21
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/go-redis/redismock/v9 v9.2.0
	github.com/goccy/go-json v0.10.3
	github.com/google/go-cmp v0.6.0
	github.com/nats-io/nats.go v1.37.0
	github.com/newrelic/go-agent v2.13.0+incompatible
	github.com/testcontainers/testcontainers-go v0.33.0
	github.com/testcontainers/testcontainers-go/modules/kafka v0.33.0
	github.com/testcontainers/testcontainers-go/modules/nats v0.33.0
	github.com/warpstreamlabs/bento v1.2.0
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/trace v1.24.0
	go.uber.org/mock v0.4.0
	golang.org/x/oauth2 v0.21.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	cuelang.org/go v0.7.0 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/Jeffail/checkpoint v1.0.1 // indirect
	github.com/Jeffail/grok v1.1.0 // indirect
	github.com/Jeffail/shutdown v1.0.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.3.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/alitto/pond v1.8.3 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/asyncapi/converter-go v0.3.0 // indirect
	github.com/asyncapi/parser-go v0.4.2 // indirect
	github.com/asyncapi/spec-json-schemas/v2 v2.14.0 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/certifi/gocertifi v0.0.0-20210507211836-431795d63e8d // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cockroachdb/apd/v3 v3.2.1 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/containerd/containerd v1.7.18 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/cpuguy83/dockercfg v0.3.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/docker v27.1.1+incompatible // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/eapache/go-resiliency v1.6.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/eclipse/paho.mqtt.golang v1.4.3 // indirect
	github.com/facebookgo/clock v0.0.0-20150410010913-600d898af40a // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.2.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/gorilla/handlers v1.5.2 // indirect
	github.com/govalues/decimal v0.1.29 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.19.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/golang-lru/arc/v2 v2.0.7 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/raft v1.7.1 // indirect
	github.com/hashicorp/serf v0.10.1 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/influxdata/go-syslog/v3 v3.0.0 // indirect
	github.com/invopop/yaml v0.2.0 // indirect
	github.com/itchyny/gojq v0.12.14 // indirect
	github.com/itchyny/timefmt-go v0.1.5 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jensneuse/byte-template v0.0.0-20200214152254-4f3cf06e5c68 // indirect
	github.com/jensneuse/pipeline v0.0.0-20200117120358-9fb4de085cd6 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/linkedin/goavro/v2 v2.12.0 // indirect
	github.com/lonelycode/go-uuid v0.0.0-20141202165402-ed3ca8a15a93 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matoous/go-nanoid/v2 v2.0.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mavricknz/asn1-ber v0.0.0-20151103223136-b9df1c2f4213 // indirect
	github.com/microcosm-cc/bluemonday v1.0.25 // indirect
	github.com/minio/highwayhash v1.0.3 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/user v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mpvl/unique v0.0.0-20150818121801-cbe035fff7de // indirect
	github.com/nats-io/jwt/v2 v2.7.2 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/nats-io/stan.go v0.10.4 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/perimeterx/marshmallow v1.1.5 // indirect
	github.com/peterbourgon/g2s v0.0.0-20170223122336-d4e7ad98afea // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/quipo/dependencysolver v0.0.0-20170801134659-2b009cb4ddcc // indirect
	github.com/r3labs/sse/v2 v2.8.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rickb777/period v1.0.5 // indirect
	github.com/rickb777/plural v1.4.2 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/shirou/gopsutil/v3 v3.23.12 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tidwall/gjson v1.11.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.0.4 // indirect
	github.com/tilinna/z85 v1.0.0 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/twmb/franz-go v1.16.1 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.7.0 // indirect
	github.com/uber/jaeger-lib v2.4.2-0.20210604143007-135cf5605a6d+incompatible // indirect
	github.com/urfave/cli/v2 v2.27.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.17.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.23.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.23.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.23.1 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/sdk v1.24.0 // indirect
	go.opentelemetry.io/proto/otlp v1.1.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20240112132812-db7319d0e0e3 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240604185151-ef581f913117 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117 // indirect
	gopkg.in/cenkalti/backoff.v1 v1.1.0 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gorm.io/gorm v1.21.16 // indirect
	nhooyr.io/websocket v1.8.10 // indirect
)

replace github.com/warpstreamlabs/bento v1.2.0 => github.com/TykTechnologies/bento v0.0.0-20241108123210-93d1717c7171
