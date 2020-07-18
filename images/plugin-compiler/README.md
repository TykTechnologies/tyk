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
Plugins are loaded via `dl_open(3)` and the shared library cache,
`ld.so.cache` will be used. Therefore,even if a plugin's content
changes but the filename does not, the cached plugin will be used.

See the manpages for `dl_open(3)` and `ld.so(8)` on your platform for
more details.

## Hot reloading
Using `/tyk/reload/group` will _not_ update the plugin if you have
compiled a fresh version and used the same pathname.
