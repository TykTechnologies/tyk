# plugin-compiler

~~Does not support go modules. If your plugin has vendored modules that
are [also used by tyk
gateway](https://github.com/TykTechnologies/tyk/tree/master/vendor)
then your module will be overridden by the version that Tyk uses.~~

Since 3.2, tyk has started using go.mod and thus your vendor'd code will no longer be overridden by tyk's versions.

## Using the image
Assuming that you are in the plugin source directory and that you want to build a plugin for v3.0.4 of the the gateway,

``` shell
% docker run --rm -v `pwd`:/plugin-source tykio/tyk-plugin-compiler:v3.0.4 testplugin.so
```

You will find a `testplugin.so` in the current directory which is the file that goes into the API definition

## Testing the image

```shell
% export tag=v2.9.5
% rm -v testplugin/*.so
% docker run --rm -v `pwd`/testplugin:/plugin-source tykio/tyk-plugin-compiler:${tag} testplugin.so
% docker-compose -f test.yml up
....
```
Look for `msg="API Loaded" api_id= api_name="Goplugin test"` in the output. Test that the plugin is working correctly by,

```shell
% curl http://localhost:8080/goplugin/headers
{
  "headers": {
    "Accept": "*/*", 
    "Accept-Encoding": "gzip", 
    "Foo": "Bar", 
    "Host": "httpbin.org", 
    "User-Agent": "curl/7.68.0", 
    "X-Amzn-Trace-Id": "Root=1-606f4317-18581ac0164b5496739a5b32"
  }
}
```

The `Foo: Bar` header indicates all is well. Can be tested with `jq` like:

``` shell
% curl http://localhost:8080/goplugin/headers | jq '.headers.Foo == "Bar"'
true
```

## Building the image

This will build the image that will be used in the plugin build
step. This section is for only for informational purposes.

In the root of the repo:

``` shell
docker build --build-arg TYK_GW_TAG=v2.8.4 -t tykio/tyk-plugin-compiler:v2.8.4 -f images/plugin-compiler/Dockerfile .
```

`TYK_GW_TAG` can be any github ref.
