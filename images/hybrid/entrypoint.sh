#!/bin/bash
echo "**************************************************************************************************************"
echo "*                                                                                                            *"
echo "** Use of the Tyk Hybrid Container is subject to the End User License Agreement located in /opt/tyk/EULA.md **"
echo "*                                                                                                            *"
echo "**************************************************************************************************************"
echo ""

export TYK_GW_LISTENPORT="$PORT"
export TYK_GW_SECRET="$SECRET"
export TYK_GW_STORAGE_HOST="$REDISHOST"
export TYK_GW_STORAGE_PORT="$RPORT"
export TYK_GW_STORAGE_PASSWORD="$REDISPW"
export TYK_GW_SLAVEOPTIONS_RPCKEY="$ORGID"
export TYK_GW_SLAVEOPTIONS_APIKEY="$APIKEY"

if [ -z "$DISABLENGINX" ]; then
	echo "--> NginX Enabled"
	service nginx start
fi

if [ -z "$BINDSLUG" ]; then
	export TYK_GW_SLAVEOPTIONS_BINDTOSLUGSINSTEADOFLISTENPATHS="false"
else
	echo "--> Binding to slugs instead of listen paths"
	export TYK_GW_SLAVEOPTIONS_BINDTOSLUGSINSTEADOFLISTENPATHS="true"
fi

echo "--> Starting Tyk Hybrid"
echo ""
service redis-server start

cd /opt/tyk-gateway/
CONFPATH=/opt/tyk-gateway
./tyk --conf=$CONFPATH/tyk.conf
