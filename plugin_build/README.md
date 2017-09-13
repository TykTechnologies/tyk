# GRPC Proxy How To

To make this easier, use the `tykio/bakery` container, it will generate a plugin file from your proto
files without any additional steps.

If you do not want to use the bakery, please use the following steps...

To add a gRPC PRoxy to Tyk, you will need a go build environment that is GRPC enabled, the first half of these instructions
are lifted from the grpc-gateway project:

## Step 1: Set up the base env

First you need to install ProtocolBuffers 3.0.0-beta-3 or later.

```sh
mkdir tmp
cd tmp
git clone https://github.com/google/protobuf
cd protobuf
./autogen.sh
./configure
make
make check
sudo make install
```

Then, `go get -u` as usual the following packages:

```sh
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
go get -u github.com/golang/protobuf/protoc-gen-go
```

## Step 2. Define your service in gRPC

   your_service.proto:
   ```protobuf
   syntax = "proto3";
   package example;
   message StringMessage {
     string value = 1;
   }

   service YourService {
     rpc Echo(StringMessage) returns (StringMessage) {}
   }
   ```
## Step 3: Add a [custom option](https://cloud.google.com/service-management/reference/rpc/google.api#http) to the .proto file

   your_service.proto:
   ```diff
    syntax = "proto3";
    package example;
   +
   +import "google/api/annotations.proto";
   +
    message StringMessage {
      string value = 1;
    }

    service YourService {
   -  rpc Echo(StringMessage) returns (StringMessage) {}
   +  rpc Echo(StringMessage) returns (StringMessage) {
   +    option (google.api.http) = {
   +      post: "/v1/example/echo"
   +      body: "*"
   +    };
   +  }
    }
   ```
## Step 4: Generate gRPC stub

   ```sh
   protoc -I/usr/local/include -I. \
     -I$GOPATH/src \
     -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
     --go_out=plugins=grpc:. \
     path/to/your_service.proto
   ```

It will generate a stub file `path/to/your_service.pb.go`.


## Step 5: Generate reverse-proxy

   ```sh
   protoc -I/usr/local/include -I. \
     -I$GOPATH/src \
     -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
     --grpc-gateway_out=logtostderr=true:. \
     path/to/your_service.proto
   ```

It will generate a reverse proxy `path/to/your_service.pb.gw.go`.

Note: After generating the code for each of the stubs, in order to build the code, you will want to run `go get .` from the directory containing the stubs.

## Step 6: Create the gRPC Proxy plugin for Tyk:

Copy the wrapper files from the [Tyk Github Repo](https://github.com/Tyktechnologies/tyk), they are:

- `plugin_build/opts.go`
- `plugin_build/wrap.go`

Copy these to the same directory as your stubs.

Open both of these files and remove the `// +build ignore` comment from the first line

Open the ``*.pb.gw.go` and `*.pb.go` files, you must change the package name from whatever was generated, to `main`, so the
header for all files should read:

    ```go
    package main
    ```

Now you must edit the `opts.go` file:

1. For specific gRPC options, edit the `getOpts()`` return value with the gRPC Options you need for your gateway
2. Change the name of `var doRegister = changeMe` to whatever is in the `*.pb.gw.go` file, it will be something like:

    ```RegisterYourServiceHandlerFromEndpoint```

Save the files

Now to build the plugin.so file, you just need to run:

    ```sh
    go build --buildmode=plugin
    ```

This should generate a `*.so` file.

## Step 7: Create a manifest file

You must create a manifest file that looks something like this:

    ```js
    {
        "file_list": ["plugin.so"],
        "custom_middleware": {
            "grpc_proxy": {
                "path": "plugin.so",
            },
            "driver": "grpc_proxy"
        }
    }
    ```

Replace `plugin.so` with your `*.so` plugin file name, you must do this in both places.

## Step 8. Create a bundle

This assumes you have the `tyk-cli` in your path:

    ```sh
    tyk-cli bundle build . -y
    ```

This wil generate a bundle that you can put onto an asset server, add this bundle to your API definition and start
your gateway