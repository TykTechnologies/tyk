#!/bin/bash

echo "Init local setup to domain: $1"
sudo /opt/tyk-gateway/install/setup.sh --dashboard=1 --listenport=8080 --redishost=localhost --redisport=6379 --domain=$1 --mongo=mongodb://localhost/tyk_analytics