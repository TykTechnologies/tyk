# Scripts

## amqp_load_generator

AMQP load generator, intended for testing purposes. Publishes messages to a RabbitMQ queue using the specified protocol.

```
$ go run amqp_load_generator.go -h
Usage: amqp_load_generator [options]

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
➜  scripts git:(master) ✗ go run amqp_load_generator.go --protocol amqp_1
Publishing message to amqp_1: {payload: 1744619969422}
Publishing message to amqp_1: {payload: 1744619970429}
Publishing message to amqp_1: {payload: 1744619971436}
Publishing message to amqp_1: {payload: 1744619972439}
Publishing message to amqp_1: {payload: 1744619973450}
Publishing message to amqp_1: {payload: 1744619974460}
...
```

* Queue name is `tyk-streams-test-queue` by default. 
* Exchange name is `tyk-streams-test-exchange` by default. It's only required for amqp_0_9.

### Installing RabbitMQ

In order to run RabbitMQ 4.0.x on your local, you can simply run it in a Docker container:

```shell
docker run -it --rm --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:4.0-management
```

The management UI can be accessed using a Web browser at http://localhost:15672/

You may need to enable `rabbitmq_management` plugin, but it's generally enabled by default. If it's not, you should 
check out the documentation: https://www.rabbitmq.com/docs/management#getting-started

### Further reading

https://www.rabbitmq.com/tutorials/amqp-concepts
https://www.rabbitmq.com/docs/publishers
https://www.rabbitmq.com/tutorials/tutorial-one-go
https://www.rabbitmq.com/docs/next/amqp
https://www.cloudamqp.com/blog/part1-rabbitmq-for-beginners-what-is-rabbitmq.html