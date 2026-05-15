package kafka

import (
	"context"
	"errors"
	"fmt"

	"github.com/IBM/sarama"

	"github.com/warpstreamlabs/bento/public/service"

	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/oauth"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

func saslField() *service.ConfigField {
	return service.NewObjectListField("sasl",
		service.NewStringAnnotatedEnumField("mechanism", map[string]string{
			"none":          "Disable sasl authentication",
			"PLAIN":         "Plain text authentication.",
			"OAUTHBEARER":   "OAuth Bearer based authentication.",
			"SCRAM-SHA-256": "SCRAM based authentication as specified in RFC5802.",
			"SCRAM-SHA-512": "SCRAM based authentication as specified in RFC5802.",
		}).
			Description("The SASL mechanism to use."),
		service.NewStringField("username").
			Description("A username to provide for PLAIN or SCRAM-* authentication.").
			Default(""),
		service.NewStringField("password").
			Description("A password to provide for PLAIN or SCRAM-* authentication.").
			Default("").Secret(),
		service.NewStringField("token").
			Description("The token to use for a single session's OAUTHBEARER authentication.").
			Default(""),
		service.NewStringMapField("extensions").
			Description("Key/value pairs to add to OAUTHBEARER authentication requests.").
			Optional(),
	).
		Description("Specify one or more methods of SASL authentication. SASL is tried in order; if the broker supports the first mechanism, all connections will use that mechanism. If the first mechanism fails, the client will pick the first supported mechanism. If the broker does not support any client mechanisms, connections will fail.").
		Advanced().Optional().
		Example(
			[]any{
				map[string]any{
					"mechanism": "SCRAM-SHA-512",
					"username":  "foo",
					"password":  "bar",
				},
			},
		)
}

func saslMechanismsFromConfig(c *service.ParsedConfig) ([]sasl.Mechanism, error) {
	if !c.Contains("sasl") {
		return nil, nil
	}

	sList, err := c.FieldObjectList("sasl")
	if err != nil {
		return nil, err
	}

	var mechanisms []sasl.Mechanism
	var mechanism sasl.Mechanism
	for i, mConf := range sList {
		mechStr, err := mConf.FieldString("mechanism")
		if err == nil {
			switch mechStr {
			case "", "none":
				continue
			case "PLAIN":
				mechanism, err = plainSaslFromConfig(mConf)
				mechanisms = append(mechanisms, mechanism)
			case "OAUTHBEARER":
				mechanism, err = oauthSaslFromConfig(mConf)
				mechanisms = append(mechanisms, mechanism)
			case "SCRAM-SHA-256":
				mechanism, err = scram256SaslFromConfig(mConf)
				mechanisms = append(mechanisms, mechanism)
			case "SCRAM-SHA-512":
				mechanism, err = scram512SaslFromConfig(mConf)
				mechanisms = append(mechanisms, mechanism)
			default:
				err = fmt.Errorf("unknown mechanism: %v", mechStr)
			}
		}
		if err != nil {
			if len(sList) == 1 {
				return nil, err
			}
			return nil, fmt.Errorf("mechanism %v: %w", i, err)
		}
	}

	return mechanisms, nil
}

func plainSaslFromConfig(c *service.ParsedConfig) (sasl.Mechanism, error) {
	username, err := c.FieldString("username")
	if err != nil {
		return nil, err
	}
	password, err := c.FieldString("password")
	if err != nil {
		return nil, err
	}
	return plain.Plain(func(c context.Context) (plain.Auth, error) {
		return plain.Auth{
			User: username,
			Pass: password,
		}, nil
	}), nil
}

func oauthSaslFromConfig(c *service.ParsedConfig) (sasl.Mechanism, error) {
	token, err := c.FieldString("token")
	if err != nil {
		return nil, err
	}
	var extensions map[string]string
	if c.Contains("extensions") {
		if extensions, err = c.FieldStringMap("extensions"); err != nil {
			return nil, err
		}
	}
	return oauth.Oauth(func(c context.Context) (oauth.Auth, error) {
		return oauth.Auth{
			Token:      token,
			Extensions: extensions,
		}, nil
	}), nil
}

func scram256SaslFromConfig(c *service.ParsedConfig) (sasl.Mechanism, error) {
	username, err := c.FieldString("username")
	if err != nil {
		return nil, err
	}
	password, err := c.FieldString("password")
	if err != nil {
		return nil, err
	}
	return scram.Sha256(func(c context.Context) (scram.Auth, error) {
		return scram.Auth{
			User: username,
			Pass: password,
		}, nil
	}), nil
}

func scram512SaslFromConfig(c *service.ParsedConfig) (sasl.Mechanism, error) {
	username, err := c.FieldString("username")
	if err != nil {
		return nil, err
	}
	password, err := c.FieldString("password")
	if err != nil {
		return nil, err
	}
	return scram.Sha512(func(c context.Context) (scram.Auth, error) {
		return scram.Auth{
			User: username,
			Pass: password,
		}, nil
	}), nil
}

//------------------------------------------------------------------------------

// SASL specific error types.
var (
	ErrUnsupportedSASLMechanism = errors.New("unsupported SASL mechanism")
)

const (
	saramaFieldSASL            = "sasl"
	saramaFieldSASLMechanism   = "mechanism"
	saramaFieldSASLUser        = "user"
	saramaFieldSASLPassword    = "password"
	saramaFieldSASLAccessToken = "access_token"
	saramaFieldSASLTokenCache  = "token_cache"
	saramaFieldSASLTokenKey    = "token_key"
)

// SaramaSASLField returns a field spec definition for SASL within the sarama
// components.
func SaramaSASLField() *service.ConfigField {
	return service.NewObjectField(saramaFieldSASL,
		service.NewStringAnnotatedEnumField(saramaFieldSASLMechanism,
			map[string]string{
				"none":          "Default, no SASL authentication.",
				"PLAIN":         "Plain text authentication. NOTE: When using plain text auth it is extremely likely that you'll also need to [enable TLS](#tlsenabled).",
				"OAUTHBEARER":   "OAuth Bearer based authentication.",
				"SCRAM-SHA-256": "Authentication using the SCRAM-SHA-256 mechanism.",
				"SCRAM-SHA-512": "Authentication using the SCRAM-SHA-512 mechanism.",
			}).
			Description("The SASL authentication mechanism, if left empty SASL authentication is not used.").
			Default("none"),
		service.NewStringField(saramaFieldSASLUser).
			Description("A PLAIN username. It is recommended that you use environment variables to populate this field.").
			Example("${USER}").
			Default(""),
		service.NewStringField(saramaFieldSASLPassword).
			Description("A PLAIN password. It is recommended that you use environment variables to populate this field.").
			Example("${PASSWORD}").
			Default("").
			Secret(),
		service.NewStringField(saramaFieldSASLAccessToken).
			Description("A static OAUTHBEARER access token").
			Default(""),
		service.NewStringField(saramaFieldSASLTokenCache).
			Description("Instead of using a static `access_token` allows you to query a [`cache`](/docs/components/caches/about) resource to fetch OAUTHBEARER tokens from").
			Default(""),
		service.NewStringField(saramaFieldSASLTokenKey).
			Description("Required when using a `token_cache`, the key to query the cache with for tokens.").
			Default(""),
	).
		Description("Enables SASL authentication.").
		Optional().
		Advanced()
}

// ApplySaramaSASLFromParsed applies a parsed config containing a SASL field to
// a sarama.Config.
func ApplySaramaSASLFromParsed(pConf *service.ParsedConfig, mgr *service.Resources, conf *sarama.Config) error {
	pConf = pConf.Namespace(saramaFieldSASL)

	mechanism, err := pConf.FieldString(saramaFieldSASLMechanism)
	if err != nil {
		return err
	}

	username, err := pConf.FieldString(saramaFieldSASLUser)
	if err != nil {
		return nil
	}

	password, err := pConf.FieldString(saramaFieldSASLPassword)
	if err != nil {
		return nil
	}

	accessToken, err := pConf.FieldString(saramaFieldSASLAccessToken)
	if err != nil {
		return nil
	}

	tokenCache, err := pConf.FieldString(saramaFieldSASLTokenCache)
	if err != nil {
		return nil
	}

	tokenKey, err := pConf.FieldString(saramaFieldSASLTokenKey)
	if err != nil {
		return nil
	}

	switch mechanism {
	case sarama.SASLTypeOAuth:
		var tp sarama.AccessTokenProvider
		var err error

		if tokenCache != "" {
			if tp, err = newCacheAccessTokenProvider(mgr, tokenCache, tokenKey); err != nil {
				return err
			}
		} else {
			if tp, err = newStaticAccessTokenProvider(accessToken); err != nil {
				return err
			}
		}
		conf.Net.SASL.TokenProvider = tp
		conf.Net.SASL.Mechanism = sarama.SASLMechanism(mechanism)
	case sarama.SASLTypeSCRAMSHA256:
		conf.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &XDGSCRAMClient{HashGeneratorFcn: SHA256}
		}
		conf.Net.SASL.User = username
		conf.Net.SASL.Password = password
		conf.Net.SASL.Mechanism = sarama.SASLMechanism(mechanism)
	case sarama.SASLTypeSCRAMSHA512:
		conf.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &XDGSCRAMClient{HashGeneratorFcn: SHA512}
		}
		conf.Net.SASL.User = username
		conf.Net.SASL.Password = password
		conf.Net.SASL.Mechanism = sarama.SASLMechanism(mechanism)
	case sarama.SASLTypePlaintext:
		conf.Net.SASL.User = username
		conf.Net.SASL.Password = password
		conf.Net.SASL.Mechanism = sarama.SASLMechanism(mechanism)
	case "", "none":
		return nil
	default:
		return ErrUnsupportedSASLMechanism
	}

	conf.Net.SASL.Enable = true

	return nil
}

//------------------------------------------------------------------------------

// cacheAccessTokenProvider fetches SASL OAUTHBEARER access tokens from a cache.
type cacheAccessTokenProvider struct {
	mgr       *service.Resources
	cacheName string
	key       string
}

func newCacheAccessTokenProvider(mgr *service.Resources, cache, key string) (*cacheAccessTokenProvider, error) {
	if !mgr.HasCache(cache) {
		return nil, fmt.Errorf("cache resource '%v' was not found", cache)
	}
	return &cacheAccessTokenProvider{
		mgr:       mgr,
		cacheName: cache,
		key:       key,
	}, nil
}

func (c *cacheAccessTokenProvider) Token() (*sarama.AccessToken, error) {
	var tok []byte
	var terr error
	if err := c.mgr.AccessCache(context.Background(), c.cacheName, func(cache service.Cache) {
		tok, terr = cache.Get(context.Background(), c.key)
	}); err != nil {
		return nil, fmt.Errorf("failed to obtain cache resource '%v': %v", c.cacheName, err)
	}
	if terr != nil {
		return nil, terr
	}
	return &sarama.AccessToken{Token: string(tok)}, nil
}

//------------------------------------------------------------------------------

// staticAccessTokenProvider provides a static SASL OAUTHBEARER access token.
type staticAccessTokenProvider struct {
	token string
}

func newStaticAccessTokenProvider(token string) (*staticAccessTokenProvider, error) {
	return &staticAccessTokenProvider{token}, nil
}

func (s *staticAccessTokenProvider) Token() (*sarama.AccessToken, error) {
	return &sarama.AccessToken{Token: s.token}, nil
}
