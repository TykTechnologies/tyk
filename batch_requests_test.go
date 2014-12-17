//package main
//
//import (
//	"github.com/justinas/alice"
//	"net/http"
//	"net/http/httptest"
//	"net/url"
//	"testing"
//	"time"
//	"bytes"
//)
//
//func createBatchTestSession() SessionState {
//	var thisSession SessionState
//	thisSession.Rate = 1.0
//	thisSession.Allowance = thisSession.Rate
//	thisSession.LastCheck = time.Now().Unix()
//	thisSession.Per = 100000
//	thisSession.Expires = -1
//	thisSession.QuotaRenewalRate = 30000000
//	thisSession.QuotaRenews = time.Now().Unix()
//	thisSession.QuotaRemaining = 10
//	thisSession.QuotaMax = 10
//
//	return thisSession
//}
//
//func getBatchTestChain(spec APISpec) http.Handler {
//	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
//	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
//	spec.Init(&redisStore, &redisStore, healthStore)
//	remote, _ := url.Parse("http://httpbin.org/")
//	proxy := TykNewSingleHostReverseProxy(remote)
//	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
//	tykMiddleware := TykMiddleware{spec, proxy}
//	chain := alice.New(
//		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
//		CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware),
//		CreateMiddleware(&VersionCheck{tykMiddleware}, tykMiddleware),
//		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
//		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
//		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)
//
//	return chain
//}
//
//var BatchTestDef string = `
//
//	{
//		"name": "Tyk Test API",
//		"api_id": "987999",
//		"org_id": "default",
//		"definition": {
//			"location": "header",
//			"key": "version"
//		},
//		"auth": {
//			"auth_header_name": "authorization"
//		},
//		"version_data": {
//			"not_versioned": true,
//			"versions": {
//				"Default": {
//					"name": "Default",
//					"expires": "3000-01-02 15:04",
//					"paths": {
//						"ignored": [],
//						"black_list": [],
//						"white_list": []
//					}
//				}
//			}
//		},
//		"event_handlers": {
//			"events": {}
//		},
//		"proxy": {
//			"listen_path": "/v1/",
//			"target_url": "http://httpbin.org",
//			"strip_listen_path": true
//		},
//		"enable_batch_request_support": true
//	}
//
//`
//
//var testBatchRequest string = `
//
//{
//    "requests": [
//        {
//            "method": "GET",
//            "headers": {
//                "test-header-1": "test-1",
//                "test-header-2": "test-2"
//            },
//            "body": "",
//            "relative_url": "get/?param1=this"
//        },
//        {
//            "method": "POST",
//            "headers": {},
//            "body": "TEST BODY",
//            "relative_url": "post/"
//        },
//        {
//            "method": "PUT",
//            "headers": {},
//            "body": "",
//            "relative_url": "put/"
//        }
//    ],
//    "suppress_parallel_execution": false
//}
//
//`
//
//func TestBatchSuccess(t *testing.T) {
//	spec := createDefinitionFromString(BatchTestDef)
//	spec.Init(&redisStore, &redisStore, healthStore)
//
//
//	batchHandler := BatchRequestHandler{API: &spec}
//	batchHandler.HandleBatchRequest(recorder, req)
//
//}
