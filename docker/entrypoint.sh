#!/bin/sh
redis-server &

npm run --prefix /opt/countries start &

/opt/tyk-gateway/tyk --conf=/opt/tyk-gateway/tyk.conf