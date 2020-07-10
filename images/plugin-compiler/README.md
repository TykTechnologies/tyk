# Tyk Plugin compiler

## Building a plugin
Navigate to where your plugin is and build using a docker volume to
mount your code into the image. Since the vendor directory needs to be
identical between the gateway build and the plugin build, this means
that you should pull the version of this image corresponding to the
gateway version you are using.

This also implies that if your plugin has vendored modules that are
also used by Tyk gateway then your module will be overridden by the
version that Tyk uses.

```shellsession
% docker run -v `pwd`:/plugin-source tykio/tyk-plugin-compiler:v2.9.4.2 myplugin.so
```

You will find a myplugin.so in the current directory which is the file
that goes into the API definition

## Plugin aliasing
Due to the way that `dl_open(3)` works, the filename needs to change
for `libdl` to recognise that the plugin has been updated. Else, the
cached value from `ld.so.cache` will be used.

## Hot reloading
Using `/tyk/reload/group` will _not_ update the plugin if you have
compiled a fresh version and used the same pathname.
