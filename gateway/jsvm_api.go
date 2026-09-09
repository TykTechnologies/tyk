package gateway

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// JSVMAPIHelper contains the shared business logic for JS API bindings.
// Both otto (JSVM.LoadTykJSApi) and goja (GojaJSVM.registerAPI) delegate
// to these methods; only the VM value-wrapping differs.
type JSVMAPIHelper struct {
	Spec   *APISpec
	Gw     *Gateway
	Log    *logrus.Entry
	RawLog *logrus.Logger
	Store  *storage.RedisCluster
}

// JSVM storage binding limits. All keys live under jsvmStoreKeyPrefix so
// plugins cannot read or write gateway-internal keys (sessions, quotas, ...).
const (
	jsvmStoreKeyPrefix   = "jsvm-store:"
	jsvmStoreMaxKeyLen   = 256
	jsvmStoreMaxValueLen = 64 * 1024
	jsvmStoreOpTimeout   = 2 * time.Second
)

var errJSVMStoreUnavailable = errors.New("JSVM storage is not available")

func (h *JSVMAPIHelper) LogMessage(msg string) {
	h.Log.WithFields(logrus.Fields{
		"type": "log-msg",
	}).Info(msg)
}

func (h *JSVMAPIHelper) RawLogMessage(msg string) {
	h.RawLog.Print(msg + "\n")
}

func (h *JSVMAPIHelper) B64Decode(in string) (string, error) {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		out, err = base64.RawStdEncoding.DecodeString(in)
		if err != nil {
			h.Log.WithError(err).Error("Failed to base64 decode")
			return "", err
		}
	}
	return string(out), nil
}

func (h *JSVMAPIHelper) B64Encode(in string) string {
	return base64.StdEncoding.EncodeToString([]byte(in))
}

func (h *JSVMAPIHelper) RawB64Decode(in string) (string, error) {
	out, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		h.Log.WithError(err).Error("Failed to base64 decode")
		return "", err
	}
	return string(out), nil
}

func (h *JSVMAPIHelper) RawB64Encode(in string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(in))
}

func (h *JSVMAPIHelper) MakeHTTPRequest(jsonHRO string) (string, error) {
	if jsonHRO == "undefined" {
		return "", nil
	}
	hro := TykJSHttpRequest{}
	if err := json.Unmarshal([]byte(jsonHRO), &hro); err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to deserialise HTTP Request object")
		return "", err
	}

	domain := hro.Domain
	data := url.Values{}
	for k, v := range hro.FormData {
		data.Set(k, v)
	}

	u, err := url.ParseRequestURI(domain + hro.Resource)
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to parse request URI")
		return "", err
	}
	urlStr := u.String()

	var d string
	if hro.Body != "" {
		d = hro.Body
	} else if len(hro.FormData) > 0 {
		d = data.Encode()
	}

	var r *http.Request
	if d != "" {
		r, err = http.NewRequest(hro.Method, urlStr, strings.NewReader(d))
	} else {
		r, err = http.NewRequest(hro.Method, urlStr, nil)
	}
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to create HTTP request")
		return "", err
	}

	ignoreCanonical := h.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for k, v := range hro.Headers {
		setCustomHeader(r.Header, k, v, ignoreCanonical)
	}
	r.Close = true

	maxSSLVersion := h.Gw.GetConfig().ProxySSLMaxVersion
	if h.Spec.Proxy.Transport.SSLMaxVersion > 0 {
		maxSSLVersion = h.Spec.Proxy.Transport.SSLMaxVersion
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MaxVersion: maxSSLVersion,
	}}

	if cert := h.Gw.getUpstreamCertificate(r.Host, h.Spec); cert != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}

	if h.Gw.GetConfig().ProxySSLInsecureSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	if h.Spec.Proxy.Transport.SSLInsecureSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	tr.DialTLS = h.Gw.customDialTLSCheck(h.Spec, tr.TLSClientConfig)
	tr.Proxy = proxyFromAPI(h.Spec)

	client := &http.Client{Transport: tr}
	resp, err := client.Do(r)
	if err != nil {
		h.Log.WithError(err).Error("Request failed")
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to read response body")
		return "", err
	}
	bodyStr := string(body)
	tykResp := TykJSHttpResponse{
		Code:        resp.StatusCode,
		Body:        bodyStr,
		Headers:     resp.Header,
		CodeComp:    resp.StatusCode,
		BodyComp:    bodyStr,
		HeadersComp: resp.Header,
	}

	retAsStr, err := json.Marshal(tykResp)
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to encode response")
		return "", err
	}
	return string(retAsStr), nil
}

func (h *JSVMAPIHelper) GetKeyData(apiKey, apiID string) string {
	obj, _ := h.Gw.handleGetDetail(apiKey, apiID, "", false)
	bs, err := json.Marshal(obj)
	if err != nil {
		h.Log.WithError(err).Error("Failed to encode key data")
		return "{}"
	}
	return string(bs)
}

func (h *JSVMAPIHelper) SetKeyData(apiKey, encodedSession, suppressReset string) error {
	newSession := user.SessionState{}
	if err := json.Unmarshal([]byte(encodedSession), &newSession); err != nil {
		h.Log.WithError(err).Error("Failed to decode the sesison data")
		return err
	}
	if err := h.Gw.doAddOrUpdate(apiKey, &newSession, suppressReset == "1", false); err != nil {
		h.Log.WithError(err).Error("Failed to update key data")
		return err
	}
	return nil
}

// storeClient returns the raw redis client for the JSVM store, and validates
// and prefixes the key. The raw client is used (rather than RedisCluster's
// methods) so every op gets a hard timeout via context and the prefix cannot
// be bypassed by key hashing (fixKey hashes before prefixing when HashKeys
// is on, which would break namespacing guarantees).
func (h *JSVMAPIHelper) storeClient(key string) (redis.UniversalClient, string, error) {
	if h.Store == nil {
		return nil, "", errJSVMStoreUnavailable
	}
	if key == "" || len(key) > jsvmStoreMaxKeyLen {
		return nil, "", fmt.Errorf("storage key must be 1-%d bytes", jsvmStoreMaxKeyLen)
	}
	client, err := h.Store.Client()
	if err != nil {
		h.Log.WithError(err).Error("JSVM storage: failed to get redis client")
		return nil, "", err
	}
	return client, jsvmStoreKeyPrefix + key, nil
}

// StorageGet retrieves a key from the JSVM store. A missing key returns
// found=false with no error; err is only non-nil on storage failure so
// callers can distinguish "absent" from "Redis down".
func (h *JSVMAPIHelper) StorageGet(key string) (value string, found bool, err error) {
	client, fixedKey, err := h.storeClient(key)
	if err != nil {
		return "", false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), jsvmStoreOpTimeout)
	defer cancel()

	value, err = client.Get(ctx, fixedKey).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		h.Log.WithError(err).Error("JSVM storage: failed to get key")
		return "", false, err
	}
	return value, true, nil
}

// StorageSet stores a value in the JSVM store. ttlSeconds 0 means no expiry.
func (h *JSVMAPIHelper) StorageSet(key, value string, ttlSeconds int64) error {
	client, fixedKey, err := h.storeClient(key)
	if err != nil {
		return err
	}
	if len(value) > jsvmStoreMaxValueLen {
		return fmt.Errorf("storage value exceeds %d bytes", jsvmStoreMaxValueLen)
	}
	ctx, cancel := context.WithTimeout(context.Background(), jsvmStoreOpTimeout)
	defer cancel()

	if err := client.Set(ctx, fixedKey, value, time.Duration(ttlSeconds)*time.Second).Err(); err != nil {
		h.Log.WithError(err).Error("JSVM storage: failed to set key")
		return err
	}
	return nil
}

// StorageSetNX stores a value only if the key does not exist (SET NX EX).
// Returns true if this call claimed the key.
func (h *JSVMAPIHelper) StorageSetNX(key, value string, ttlSeconds int64) (bool, error) {
	client, fixedKey, err := h.storeClient(key)
	if err != nil {
		return false, err
	}
	if len(value) > jsvmStoreMaxValueLen {
		return false, fmt.Errorf("storage value exceeds %d bytes", jsvmStoreMaxValueLen)
	}
	ctx, cancel := context.WithTimeout(context.Background(), jsvmStoreOpTimeout)
	defer cancel()

	set, err := client.SetNX(ctx, fixedKey, value, time.Duration(ttlSeconds)*time.Second).Result()
	if err != nil {
		h.Log.WithError(err).Error("JSVM storage: failed to setnx key")
		return false, err
	}
	return set, nil
}

// StorageDel removes a key from the JSVM store.
func (h *JSVMAPIHelper) StorageDel(key string) error {
	client, fixedKey, err := h.storeClient(key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), jsvmStoreOpTimeout)
	defer cancel()

	if err := client.Del(ctx, fixedKey).Err(); err != nil {
		h.Log.WithError(err).Error("JSVM storage: failed to delete key")
		return err
	}
	return nil
}

// StorageTTL returns the remaining TTL of a key in seconds, following redis
// semantics: -1 means no expiry, -2 means the key does not exist.
func (h *JSVMAPIHelper) StorageTTL(key string) (int64, error) {
	client, fixedKey, err := h.storeClient(key)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), jsvmStoreOpTimeout)
	defer cancel()

	ttl, err := client.TTL(ctx, fixedKey).Result()
	if err != nil {
		h.Log.WithError(err).Error("JSVM storage: failed to get key TTL")
		return 0, err
	}
	// go-redis passes the -1/-2 sentinels through as raw durations.
	if ttl < 0 {
		return int64(ttl), nil
	}
	return int64(ttl / time.Second), nil
}

// StorageIncr atomically increments a key and returns the new value as a
// string (JS numbers lose precision past 2^53). ttlSeconds is applied only
// when the increment created the key, matching IncrememntWithExpire semantics.
func (h *JSVMAPIHelper) StorageIncr(key string, ttlSeconds int64) (string, error) {
	client, fixedKey, err := h.storeClient(key)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), jsvmStoreOpTimeout)
	defer cancel()

	val, err := client.Incr(ctx, fixedKey).Result()
	if err != nil {
		h.Log.WithError(err).Error("JSVM storage: failed to increment key")
		return "", err
	}
	if val == 1 && ttlSeconds > 0 {
		if err := client.Expire(ctx, fixedKey, time.Duration(ttlSeconds)*time.Second).Err(); err != nil {
			h.Log.WithError(err).Error("JSVM storage: failed to set expire on incremented key")
			return "", err
		}
	}
	return strconv.FormatInt(val, 10), nil
}

func (h *JSVMAPIHelper) BatchRequest(requestSet string) (string, error) {
	h.Log.Debug("Batch input is: ", requestSet)
	unsafeBatchHandler := BatchRequestHandler{Gw: h.Gw}
	bs, err := unsafeBatchHandler.ManualBatchRequest([]byte(requestSet))
	if err != nil {
		h.Log.WithError(err).Error("Batch request error")
		return "", err
	}
	return string(bs), nil
}
