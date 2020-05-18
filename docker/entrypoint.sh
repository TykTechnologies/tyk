#!/bin/sh
cat /opt/tyk-gateway/apps/countries.json
redis-server &

npm run --prefix /opt/countries start &

/opt/tyk-gateway/tyk --conf=/opt/tyk-gateway/tyk.conf