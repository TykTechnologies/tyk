# build-env

Docker environment used to build official images.

This used be here but now lives at the repo attached to
[tyk-build-env](https://hub.docker.com/r/tykio/tyk-build-env)

# plugin-compiler

The usecase is that you have a plugin (probably Go) that you require
to be built.

Navigate to where your plugin is and build using a docker volume to
mount your code into the image. Since the vendor directory needs to be
identical between the gateway build and the plugin build, this means
that you should pull the version of this image corresponding to the
gateway version you are using.

This also implies that if your plugin has vendored modules that are
[also used by Tyk
gateway](https://github.com/TykTechnologies/tyk/tree/master/vendor)
then your module will be overridden by the version that Tyk uses. 

``` shell
cd ${GOPATH}/src/tyk-plugin
docker run -v `pwd`:/go/src/plugin-build plugin-build pre
```

You will find a `pre.so` in the current directory which is the file
that goes into the API definition

## Building the image

This will build the image that will be used in the plugin build
step. This section is for only for informational purposes.

In the root of the repo:

``` shell
docker build --build-arg TYK_GW_TAG=v2.8.4 -t tyk-plugin-build-2.8.4 .
```

TYK_GW_TAG refers to the _tag_ in github corresponding to a released
version.
