module github.com/TykTechnologies/tyk

go 1.21.11

require (
	github.com/Jeffail/tunny v0.1.4
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/TykTechnologies/again v0.0.0-20190805133618-6ad301e7eaed
	github.com/TykTechnologies/circuitbreaker v2.2.2+incompatible
	github.com/TykTechnologies/drl v0.0.0-20231218155806-88e4363884a2
	github.com/TykTechnologies/goautosocket v0.0.0-20190430121222-97bfa5e7e481
	github.com/TykTechnologies/gojsonschema v0.0.0-20170222154038-dcb3e4bb7990
	github.com/TykTechnologies/gorpc v0.0.0-20210624160652-fe65bda0ccb9
	github.com/TykTechnologies/goverify v0.0.0-20220808203004-1486f89e7708
	github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20240705065952-ae6008677a48
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
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/gocraft/health v0.0.0-20170925182251-8675af27fef0
	github.com/gofrs/uuid v4.4.0+incompatible
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/consul/api v1.29.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.7.0
	github.com/hashicorp/vault/api v1.14.0
	github.com/jensneuse/abstractlogger v0.0.4
	github.com/justinas/alice v1.2.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lonelycode/osin v0.0.0-20160423095202-da239c9dacb6
	github.com/mavricknz/ldap v0.0.0-20160227184754-f5a958005e43
	github.com/miekg/dns v1.1.61
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0
	github.com/nsf/jsondiff v0.0.0-20230430225905-43f6cf3098c1 // test
	github.com/opentracing/opentracing-go v1.2.0
	github.com/openzipkin/zipkin-go v0.4.3
	github.com/oschwald/maxminddb-golang v1.13.0
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/pires/go-proxyproto v0.7.0
	github.com/pmylund/go-cache v2.1.0+incompatible
	github.com/robertkrimen/otto v0.4.0
	github.com/rs/cors v1.11.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.11.0
	github.com/stretchr/testify v1.9.0 // test
	github.com/uber/jaeger-client-go v2.30.1-0.20220110192849-8d8e8fcfd04d+incompatible
	github.com/valyala/fasthttp v1.55.0 // test
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.25.0
	golang.org/x/net v0.27.0
	golang.org/x/sync v0.7.0
	google.golang.org/grpc v1.64.0
	google.golang.org/grpc/examples v0.0.0-20220317213542-f95b001a48df // test
	google.golang.org/protobuf v1.34.2
	gopkg.in/vmihailenco/msgpack.v2 v2.9.2
	gopkg.in/xmlpath.v2 v2.0.0-20150820204837-860cbeca3ebc
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/TykTechnologies/exp/pkg/limiters v0.0.0-20231219151617-0c4f9315fe5c
	github.com/go-redsync/redsync/v4 v4.11.0
	github.com/redis/go-redis/v9 v9.5.3
)

require (
	github.com/Jeffail/gabs/v2 v2.7.0
	github.com/TykTechnologies/graphql-go-tools/v2 v2.0.0-20240509085643-e95cdc317e1d
	github.com/TykTechnologies/kin-openapi v0.90.0
	github.com/TykTechnologies/opentelemetry v0.0.21
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/go-redis/redismock/v9 v9.2.0
	github.com/google/go-cmp v0.6.0
	github.com/newrelic/go-agent v2.13.0+incompatible
	go.opentelemetry.io/otel v1.27.0
	go.opentelemetry.io/otel/trace v1.27.0
	go.uber.org/mock v0.4.0
)

require (
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/IBM/sarama v1.43.1 // indirect
	github.com/Jorropo/jsync v1.0.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/TykTechnologies/cannery/v2 v2.0.0-20240822222831-3be26a04664f // indirect
	github.com/alecthomas/units v0.0.0-20231202071711-9a357b53e9c9 // indirect
	github.com/alitto/pond v1.8.3 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/asyncapi/converter-go v0.3.0 // indirect
	github.com/asyncapi/parser-go v0.4.2 // indirect
	github.com/asyncapi/spec-json-schemas/v2 v2.14.0 // indirect
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/certifi/gocertifi v0.0.0-20210507211836-431795d63e8d // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/crackcomm/go-gitignore v0.0.0-20231225121904-e25f5bc08668 // indirect
	github.com/cskr/pubsub v1.0.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/davidlazar/go-crypto v0.0.0-20200604182044-b73af7476f6c // indirect
	github.com/dchest/siphash v1.2.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/dgraph-io/badger v1.6.2 // indirect
	github.com/dgraph-io/ristretto v0.0.2 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/dustinxie/lockfree v0.0.0-20210712051436-ed0ed42fd0d6 // indirect
	github.com/eapache/go-resiliency v1.6.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/eclipse/paho.mqtt.golang v1.2.0 // indirect
	github.com/elastic/gosigar v0.14.3 // indirect
	github.com/facebookgo/clock v0.0.0-20150410010913-600d898af40a // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/gobwas/httphead v0.0.0-20180130184737-2c6c146eadee // indirect
	github.com/gobwas/pool v0.2.0 // indirect
	github.com/gobwas/ws v1.0.4 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.6 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/serf v0.10.1 // indirect
	github.com/hsanjuan/ipfs-lite v1.8.2 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/invopop/yaml v0.2.0 // indirect
	github.com/ipfs/bbloom v0.0.4 // indirect
	github.com/ipfs/boxo v0.22.0 // indirect
	github.com/ipfs/go-bitfield v1.1.0 // indirect
	github.com/ipfs/go-block-format v0.2.0 // indirect
	github.com/ipfs/go-cid v0.4.1 // indirect
	github.com/ipfs/go-cidutil v0.1.0 // indirect
	github.com/ipfs/go-datastore v0.6.0 // indirect
	github.com/ipfs/go-ds-badger v0.3.0 // indirect
	github.com/ipfs/go-ds-crdt v0.5.3 // indirect
	github.com/ipfs/go-ipfs-delay v0.0.1 // indirect
	github.com/ipfs/go-ipfs-pq v0.0.3 // indirect
	github.com/ipfs/go-ipfs-util v0.0.3 // indirect
	github.com/ipfs/go-ipld-format v0.6.0 // indirect
	github.com/ipfs/go-ipld-legacy v0.2.1 // indirect
	github.com/ipfs/go-log v1.0.5 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/ipfs/go-metrics-interface v0.0.1 // indirect
	github.com/ipfs/go-peertaskqueue v0.8.1 // indirect
	github.com/ipld/go-codec-dagpb v1.6.0 // indirect
	github.com/ipld/go-ipld-prime v0.21.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/jbenet/go-temp-err-catcher v0.1.0 // indirect
	github.com/jbenet/goprocess v0.1.4 // indirect
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
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/libp2p/go-cidranger v1.1.0 // indirect
	github.com/libp2p/go-flow-metrics v0.1.0 // indirect
	github.com/libp2p/go-libp2p v0.36.1 // indirect
	github.com/libp2p/go-libp2p-asn-util v0.4.1 // indirect
	github.com/libp2p/go-libp2p-kad-dht v0.25.2 // indirect
	github.com/libp2p/go-libp2p-kbucket v0.6.3 // indirect
	github.com/libp2p/go-libp2p-pubsub v0.11.0 // indirect
	github.com/libp2p/go-libp2p-record v0.2.0 // indirect
	github.com/libp2p/go-libp2p-routing-helpers v0.7.3 // indirect
	github.com/libp2p/go-msgio v0.3.0 // indirect
	github.com/libp2p/go-nat v0.2.0 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/libp2p/go-yamux/v4 v4.0.1 // indirect
	github.com/libp2p/zeroconf/v2 v2.2.0 // indirect
	github.com/lonelycode/go-uuid v0.0.0-20141202165402-ed3ca8a15a93 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/marten-seemann/tcp v0.0.0-20210406111302-dfbc87cc63fd // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mavricknz/asn1-ber v0.0.0-20151103223136-b9df1c2f4213 // indirect
	github.com/mikioh/tcpinfo v0.0.0-20190314235526-30a79bb1804b // indirect
	github.com/mikioh/tcpopt v0.0.0-20190314235656-172688c1accc // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multiaddr v0.13.0 // indirect
	github.com/multiformats/go-multiaddr-dns v0.3.1 // indirect
	github.com/multiformats/go-multiaddr-fmt v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/multiformats/go-multicodec v0.9.0 // indirect
	github.com/multiformats/go-multihash v0.2.3 // indirect
	github.com/multiformats/go-multistream v0.5.0 // indirect
	github.com/multiformats/go-varint v0.0.7 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo/v2 v2.19.1 // indirect
	github.com/opencontainers/runtime-spec v1.2.0 // indirect
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58 // indirect
	github.com/perimeterx/marshmallow v1.1.5 // indirect
	github.com/peterbourgon/g2s v0.0.0-20170223122336-d4e7ad98afea // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pion/datachannel v1.5.8 // indirect
	github.com/pion/dtls/v2 v2.2.12 // indirect
	github.com/pion/ice/v2 v2.3.32 // indirect
	github.com/pion/interceptor v0.1.29 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/mdns v0.0.12 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.14 // indirect
	github.com/pion/rtp v1.8.8 // indirect
	github.com/pion/sctp v1.8.20 // indirect
	github.com/pion/sdp/v3 v3.0.9 // indirect
	github.com/pion/srtp/v2 v2.0.20 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v2 v2.2.9 // indirect
	github.com/pion/turn/v2 v2.1.6 // indirect
	github.com/pion/webrtc/v3 v3.2.50 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/polydawn/refmt v0.89.0 // indirect
	github.com/prometheus/client_golang v1.19.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/quic-go v0.45.2 // indirect
	github.com/quic-go/webtransport-go v0.8.0 // indirect
	github.com/r3labs/sse/v2 v2.8.1 // indirect
	github.com/raulk/go-watchdog v1.3.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tidwall/gjson v1.11.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.0.4 // indirect
	github.com/uber/jaeger-lib v2.4.2-0.20210604143007-135cf5605a6d+incompatible // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/whyrusleeping/chunker v0.0.0-20181014151217-fe64bd25879f // indirect
	github.com/whyrusleeping/go-keyspace v0.0.0-20160322163242-5b898ac5add1 // indirect
	github.com/wlynxg/anet v0.0.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190809123943-df4f5c81cb3b // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.52.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.17.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.27.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.27.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.27.0 // indirect
	go.opentelemetry.io/otel/metric v1.27.0 // indirect
	go.opentelemetry.io/otel/sdk v1.27.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/dig v1.17.1 // indirect
	go.uber.org/fx v1.22.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
	golang.org/x/mod v0.19.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.23.0 // indirect
	gonum.org/v1/gonum v0.15.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240617180043-68d350f18fd4 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240617180043-68d350f18fd4 // indirect
	gopkg.in/cenkalti/backoff.v1 v1.1.0 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gorm.io/gorm v1.21.16 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
	nhooyr.io/websocket v1.8.10 // indirect
)

//replace github.com/TykTechnologies/graphql-go-tools => ../graphql-go-tools

//replace github.com/TykTechnologies/graphql-go-tools/v2 => ../graphql-go-tools/v2
replace github.com/TykTechnologies/storage => ../storage
