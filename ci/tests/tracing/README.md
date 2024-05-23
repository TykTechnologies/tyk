---
title: Opentelemetry e2e Tests
---

# Opentelemetry e2e Tests

This docker-compose file defines a multi-service application including the following components:

- `tyk`: This service runs an internal Tyk gateway. So if you are running this from a cold start, make sure to execute `make docker` at the root of Tyk's repo. The environment variables for the tyk service are loaded from a local file, `./configs/tyk.env`. It uses `/apps` folder to mount the preloaded APIs.
    - `redis`: This service runs another Redis server (version 4.0, based on Alpine Linux). The Redis server is configured to use an append-only file for data persistence.
    - `httpbin`: This service runs an HTTP Request & Response Service, which is a simple HTTP server for testing and debugging.

- `otel-collector`: This service runs an instance of the OpenTelemetry Collector (version 0.80.0). It is configured using the file /otel-local-config.yml, which is mounted from the local file ./tracetest/collector.config.yml.

- `tracetest`: This service runs an application from the Docker image kubeshop/tracetest:v0.11.16. It depends on the otel-collector and postgres services. It uses a provisioning file located at `/configs/tracetest/tracetest-provision.yml` and a configuration file located at `/configs/tracetest/tracetest.yml`.

It needs the following services to work:

    - `postgres`: This service runs a PostgreSQL database (version 14). It uses environment variables to set the PostgreSQL user and password. The health of the PostgreSQL service is checked by running the pg_isready command, which checks the connection to the database server.
    - `queue`: This service runs a RabbitMQ message broker, with the management plugin enabled. It checks the health of the RabbitMQ server using the rabbitmq-diagnostics check_running command.
    - `cache`: This service runs a Redis server (version 6) as a cache, with the unless-stopped restart policy. It periodically checks the health of the Redis server using the redis-cli ping command.


The `tests` folder contains all the `*.yml` declarations of tests that are going to be executed. Please take into consideration:

- the target URL for gateway APIs is `http://httpbin:80/` for HTTP APIs

# Running the tests

The following should be used for general testing:

- Build `internal/tyk-gateway` in the project root by running `make docker`
- Run `task` in this folder to run tests against the internal image
- You are able to override the docker image by setting `GATEWAY_IMAGE=<your image> task`.

# Debugging with delve

To install and use the delve debugger, run `task install:delve` with the
following parameters that configure the docker images:

- `task install:delve input=<source-image> output=<destination-image>`

If the `output` parameter is omitted, `internal/tyk-gateway` image will
be created. The command installs delve locally and then copies it into
the final image.

```
# task install:delve input=tykio/tyk-gateway:v5.3.1
task: [install:delve] go install github.com/go-delve/delve/cmd/dlv@latest
task: [install:delve] docker create --name tc tykio/tyk-gateway:v5.3.1
aa57b10afaa6f649c54958fb711830dffca0581100c030636b204a5b932eba66
task: [install:delve] docker cp $GOBIN/dlv tc:/usr/bin/dlv
Successfully copied 19.6MB to tc:/usr/bin/dlv
task: [install:delve] docker cp tc:/opt/tyk-gateway/tyk ./tyk-debug
Successfully copied 98.2MB to /root/tyk/tyk/ci/tests/tracing/tyk-debug
task: [install:delve] docker commit tc internal/tyk-gateway
sha256:8a6be7a091dd3dab140a8514e223bc231abb4f28ab7f99e839235632305f14f1
task: [install:delve] docker rm -f tc
tc
```

The task will copy out the gateway binary from the input image into `./tyk-debug`.
The binary can be used for further inspection, e.g. `go version -m tyk-debug`.

As shown, it will create `internal/tyk-gateway` image which is the default
used for the tests. If you want to create a different image, you may
pass the `output` parameter.

To use the produced image:

- `task debug=true` will run the default image with delve, use `GATEWAY_IMAGE` if you need to adjust it,
- in another terminal run `dlv connect localhost:2345` and hit `c` to continue.

Passing `debug=true` uses the `docker-compose.debug.yml` taskfile which invokes gateway over delve.

```diff
--- docker-compose.yml	2024-05-23 12:43:32.497847236 +0200
+++ docker-compose.debug.yml	2024-05-23 12:43:24.025868887 +0200
@@ -93,12 +93,20 @@
     platform: linux/amd64
     ports:
       - 9000:8080
+      - 2345:2345
     env_file:
       - ./configs/tyk.env
     volumes:
       - ./apps:/opt/tyk-gateway/apps
     depends_on:
       - redis
+    entrypoint: dlv
+    command:
+      - exec
+      - /opt/tyk-gateway/tyk
+      - --listen=:2345
+      - --api-version=2
+      - --headless
 
   tyk-checker:
     platform: linux/amd64
```
