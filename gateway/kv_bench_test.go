package gateway

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func benchKVGateway(b *testing.B) *Gateway {
	b.Helper()

	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "db_password"), []byte("s3cr3t\n"), 0o600); err != nil {
		b.Fatal(err)
	}

	b.Setenv("TYK_SECRET_DB_PASSWORD", "s3cr3t")
	b.Setenv("BENCH_DB_PASSWORD", "s3cr3t")

	conf := config.Config{
		Secrets: map[string]string{
			"db_password": "s3cr3t",
			"unused_1":    "x",
			"unused_2":    "x",
			"unused_3":    "x",
		},
	}
	conf.KV.File.BasePath = dir

	gw := NewGateway(conf, b.Context())
	gw.setTestMode(true)

	return gw
}

var benchRefs = map[string]string{
	"none":          "http://upstream.internal/",
	"legacy-env":    "env://BENCH_DB_PASSWORD",
	"legacy-secret": "secrets://db_password",
	"legacy-file":   "file://db_password",
	"kv-whole":      "kv://secrets/db_password",
	"kv-inline":     "postgres://user:$kv{secrets:db_password}@db.internal/tyk",
}

const benchAPIEntryTemplate = `{"api_definition":{` +
	`"api_id":"api-%d","name":"api %d",` +
	`"proxy":{"listen_path":"/svc-%d/","target_url":%q},` +
	`"version_data":{"not_versioned":true,"versions":{` +
	`"Default":{"name":"Default","use_extended_paths":true}}}}}`

func benchAPICollection(apis, refCount int, ref string) []byte {
	entries := make([]string, apis)

	for i := range entries {
		target := "http://upstream-" + fmt.Sprint(i) + ".internal/"
		if i < refCount {
			target = ref
		}

		entries[i] = fmt.Sprintf(benchAPIEntryTemplate, i, i, i, target)
	}

	return []byte("[" + strings.Join(entries, ",") + "]")
}

func BenchmarkReplaceSecrets(b *testing.B) {
	gw := benchKVGateway(b)
	loader := APIDefinitionLoader{Gw: gw}

	for _, apis := range []int{10, 100} {
		for _, name := range []string{"none", "legacy-env", "legacy-secret", "legacy-file", "kv-whole", "kv-inline"} {
			doc := benchAPICollection(apis, apis/10, benchRefs[name])

			b.Run(fmt.Sprintf("apis=%d/%s", apis, name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(doc)))

				for b.Loop() {
					_ = loader.replaceSecrets(doc)
				}
			})
		}
	}
}

func BenchmarkReplaceTykVariables(b *testing.B) {
	gw := benchKVGateway(b)

	cases := []struct{ name, in string }{
		{"no-tokens", "http://upstream.internal/foo/bar"},
		{"context-var", "http://upstream.internal/$tyk_context.path"},
		{"legacy-conf", "http://upstream.internal/?token=$secret_conf.db_password"},
		{"legacy-env", "http://upstream.internal/?token=$secret_env.db_password"},
		{"legacy-file", "http://upstream.internal/?token=$secret_file.db_password"},
		{"kv-inline", "http://upstream.internal/?token=$kv{secrets:db_password}"},
		{"kv-whole", "kv://secrets/db_password"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			r := httptest.NewRequest("GET", "/", nil)
			ctxSetData(r, map[string]interface{}{"path": "foo"})

			b.ReportAllocs()

			for b.Loop() {
				_ = gw.ReplaceTykVariables(r, tc.in, false)
			}
		})
	}
}

func BenchmarkReplaceTykVariables_Parallel(b *testing.B) {
	gw := benchKVGateway(b)

	for _, name := range []string{"legacy-conf", "kv-inline"} {
		in := "http://upstream.internal/?token=$secret_conf.db_password"
		if name == "kv-inline" {
			in = "http://upstream.internal/?token=$kv{secrets:db_password}"
		}

		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				r := httptest.NewRequest("GET", "/", nil)

				for pb.Next() {
					_ = gw.ReplaceTykVariables(r, in, false)
				}
			})
		})
	}
}
