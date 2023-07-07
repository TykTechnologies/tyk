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


The `tests` folder contains all the `*.yml` declarations of tests that are going to be executed against the gateway.