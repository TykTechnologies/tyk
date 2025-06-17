# Scripts

## Load Generators

This package contains multiple load generators for different protocols.

You can run them by using the command: `go run load_gen.go <type>`

### AMQP

AMQP load generator, intended for testing purposes. Publishes messages to a RabbitMQ queue using the specified protocol.

```
$ go run load_gen.go amqp -h
Usage: go run load_gen.go amqp [options]

AMQP load generator. Publishes messages to a RabbitMQ queue using the specified protocol.

Options:
  -h, --help     Print this message and exit.
      --protocol AMQP protocol version to use. Supported values: amqp_0_9, amqp_1. Default: amqp_0_9.
      --url      RabbitMQ server URL. Default: amqp://guest:guest@localhost:5672/.
      --queue    RabbitMQ queue name. Default: tyk-streams-test-queue.
      --exchange RabbitMQ exchange name, only valid for amqp_0_9 Default: tyk-streams-test-exchange.
```

Sample usage: 

```
$ go run load_gen.go amqp --protocol amqp_1
Publishing message to amqp_1: {payload: 1744619969422}
Publishing message to amqp_1: {payload: 1744619970429}
Publishing message to amqp_1: {payload: 1744619971436}
Publishing message to amqp_1: {payload: 1744619972439}
Publishing message to amqp_1: {payload: 1744619973450}
Publishing message to amqp_1: {payload: 1744619974460}
```

* Queue name is `tyk-streams-test-queue` by default. 
* Exchange name is `tyk-streams-test-exchange` by default. It's only required for amqp_0_9.

### MQTT

MQTT load generator, intended for testing purposes. Publishes messages to an MQTT broker on the specified topic.

```
$ go run load_gen.go mqtt -h
Usage: go run load_gen.go mqtt [options]

MQTT load generator. Publishes messages to an MQTT broker on the specified topic.

Options:
  -h, --help     Print this message and exit.
      --broker   MQTT broker URL. Default: tcp://localhost:1883.
      --topic    MQTT topic to publish to. Default: tyk-streams-test-topic.
      --clientid MQTT client ID. Default: tyk-mqtt-load-generator.
      --qos      MQTT QoS level (0, 1, or 2). Default: 1.
      --username MQTT username (optional).
      --password MQTT password (optional).
```

Sample usage: 

```
$ go run load_gen.go mqtt
2023/05/15 10:23:45 Connected to MQTT broker at tcp://localhost:1883
2023/05/15 10:23:46 Publishing message to MQTT topic 'tyk-streams-test-topic': {"payload":1684142626000}
2023/05/15 10:23:47 Publishing message to MQTT topic 'tyk-streams-test-topic': {"payload":1684142627000}
2023/05/15 10:23:48 Publishing message to MQTT topic 'tyk-streams-test-topic': {"payload":1684142628000}
2023/05/15 10:23:49 Publishing message to MQTT topic 'tyk-streams-test-topic': {"payload":1684142629000}
```

* Topic name is `tyk-streams-test-topic` by default.
* QoS level is `1` (at least once delivery) by default.
* The generator publishes messages at 1-second intervals.

## Broker

### RabbitMQ (AMQP / MQTT)

To run RabbitMQ 4.0.x on your local, you can run it in a Docker container:

```shell
docker run -it --rm --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:4.0-management
```

The management UI can be accessed using a Web browser at http://localhost:15672/

You may need to enable `rabbitmq_management` plugin, but it's generally enabled by default. If it's not, you should
check out the documentation: https://www.rabbitmq.com/docs/management#getting-started

#### Docker Compose

If you want to have 3 distinct RabbitMQ instances with AMQP 0-9-1, AMQP 1.0 and MQTT, you can use following `docker-compose.yml`:
```yml
version: "3.8"

services:
  rabbitmq-amqp-0-9-1:
    image: rabbitmq:3-management
    container_name: rabbitmq_amqp_0_9_1
    ports:
      - "15672:15672" # Management UI
      - "5672:5672" # AMQP port
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest
    networks:
      - rabbitmq_network

  rabbitmq-amqp-1-0:
    image: rabbitmq:3-management
    container_name: rabbitmq_amqp_1_0
    ports:
      - "15673:15672" # Management UI
      - "5673:5672" # AMQP port
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest
      RABBITMQ_ENABLED_PLUGINS_FILE: /etc/rabbitmq/custom_plugins.conf
    volumes:
      - "./rabbitmq_amqp_1_0_plugins.conf:/etc/rabbitmq/custom_plugins.conf"
    networks:
      - rabbitmq_network

  rabbitmq-mqtt:
    image: rabbitmq:3-management
    container_name: rabbitmq_mqtt
    ports:
      - "15674:15672" # Management UI
      - "5674:5672" # AMQP
      - "1883:1883" # MQTT
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest
    networks:
      - rabbitmq_network
    command: >
      bash -c "
        rabbitmq-plugins enable --offline rabbitmq_mqtt;
        rabbitmq-server
      "

networks:
  rabbitmq_network:
    driver: bridge
```

In that case, the AMQP 1.0 instance needs an additional file alongside called `rabbitmq_amqp_1_0_plugins.conf`.
This should have the following contents:
```
[rabbitmq_management,rabbitmq_amqp1_0].
```

### Mosquitto MQTT Broker

To run an MQTT broker locally for testing, you can use Eclipse Mosquitto in a Docker container:

```shell
docker run -it --rm --name mosquitto -p 1883:1883 -p 9001:9001 eclipse-mosquitto:2.0
```

For a more complete setup with authentication and persistence, you can create a custom configuration file and mount it:

```shell
docker run -it --rm --name mosquitto -p 1883:1883 -p 9001:9001 \
  -v $(pwd)/mosquitto.conf:/mosquitto/config/mosquitto.conf \
  -v $(pwd)/data:/mosquitto/data \
  -v $(pwd)/log:/mosquitto/log \
  eclipse-mosquitto:2.0
```

## Further reading

### AMQP
https://www.rabbitmq.com/tutorials/amqp-concepts
https://www.rabbitmq.com/docs/publishers
https://www.rabbitmq.com/tutorials/tutorial-one-go
https://www.rabbitmq.com/docs/next/amqp
https://www.cloudamqp.com/blog/part1-rabbitmq-for-beginners-what-is-rabbitmq.html

### MQTT
https://mqtt.org/
https://www.hivemq.com/mqtt-essentials/
https://mosquitto.org/documentation/