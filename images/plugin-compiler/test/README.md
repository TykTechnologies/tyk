# Testing the plugin compiler

## Build the plugin
`TPC_VERSION` (Tyk Plugin Compiler version) should correspond to the version you want to use.

``` shellsession
% make TPC_VERSION=v2.9.4.2-rc1
docker run --rm -v $PWD:/plugin-source tykio/tyk-plugin-compiler:v2.9.4.2-rc1 plugin.so
+ plugin_name=plugin.so
++ date +%s
+ plugin_path=1594377968-plugin.so
+ '[' -z plugin.so ']'
+ yes
+ cp -r /plugin-source/#README.md# /plugin-source/Makefile /plugin-source/apps /plugin-source/foo-plugin.go /plugin-source/plugins /plugin-source/plugins.yml /plugin-source/pre-post.json /plugin-source/tyk.conf /go/src/plugin-build
+ yes
+ cp -r /go/src/plugin-build/vendor /go/src
cp: cannot stat '/go/src/plugin-build/vendor': No such file or directory
+ true
+ rm -rf /go/src/plugin-build/vendor
+ cd /go/src/plugin-build
+ go build -buildmode=plugin -ldflags -pluginpath=1594377968-plugin.so -o plugin.so
+ mv plugin.so /plugin-source
```

## Define an API
Place this in the `apps` sub-directory. This is mounted to
`/opt/tyk-gateway/apps`. A sample definition is provided.

## Run gateway with plugins
Move the plugins into a directory called `plugins`. This will be
mounted to `/opt/tyk-gateway/middleware` in the gateway container. A
minimal `tyk.conf` is provided. Set the gateway version to use and
bring the gateway and redis up with

``` shellsession
% GW_VERSION=v2.9.4.2 docker-compose -f plugins.yml up
```

## See if the plugin works

``` shellsession
% curl -X POST http://localhost:8080/postplugin
{
  "args": {}, 
  "data": "", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "*/*", 
    "Accept-Encoding": "gzip", 
    "Content-Length": "0", 
    "Foo": "Bar", 
    "Host": "httpbin.org", 
    "User-Agent": "curl/7.68.0", 
    "X-Amzn-Trace-Id": "Root=1-5f08545c-2f91e5c4388bff04f25f1467"
  }, 
  "json": null, 
  "origin": "172.26.0.1, 106.51.77.191", 
  "url": "http://httpbin.org/post"
}
```

Note the header `Foo`.
