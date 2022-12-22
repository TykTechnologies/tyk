# build-env

Docker environment used to build official images and plugins.

This is the base image that will slowly be used in all our builds. It
is not capable of handling i386 or arm64 builds. Those builds are
handled by installing additional components in the environment section
of the pipeline.

This image will need to be updated only when upgrading the go version
or if some system dependencies for building change. This image is
mainly used internally at Tyk for CD pipelines.

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
