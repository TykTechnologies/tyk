#!/bin/bash

set -eo pipefail

usage() {

    cat <<EOF
Usage:
	./scripts/$0 <dashboard base url>

This script should be run from the repo root as it expects files (data/{org,api}.json) relative to it.
The base URL for the compose env in this repo is usually http://localhost:3000. A trailing slash is not required.
All authentication and parameters are hardcoded except for those which cannot 
EOF
}

curlf() {
    curl --header 'Content-Type:application/json' -s --show-error "$@"
}

if [ -z $1 ]; then
    usage
    exit 1
fi

db_base=${1:-"http://localhost:3000"}

org_json='{
	"owner_name": "System Test Org",
	"owner_slug": "st",
	"cname_enabled": false,
	"hybrid_enabled": true,
	"cname": ""
}'

# 1. Create org using admin authentication
orgid=$(curlf --header "admin-auth: 12345" \
	      --data "$org_json" \
	      ${db_base}/admin/organisations | jq -r '.Meta')

echo "TYK_GW_SLAVEOPTIONS_RPCKEY=${orgid}"
sed -i "" "s/TYK_GW_SLAVEOPTIONS_RPCKEY=.*/TYK_GW_SLAVEOPTIONS_RPCKEY=${orgid}/g" *.env

# 1a. Add orgid into user creation json
user_json=$(jq --arg oid $orgid '. + { org_id: $oid }' <<<'{
  "first_name": "John",
  "last_name": "Smith",
  "email_address": "bfd1e4d505@example.com",
  "password": "test123",
  "active": true
}')

#2. Create user in org from (1)
user_auth=$(curlf --header "admin-auth: 12345" \
		  --data "$user_json" \
		  ${db_base}/admin/users | jq -r '.Message')

echo "TYK_GW_SLAVEOPTIONS_APIKEY=${user_auth}"
sed -i "" "s/TYK_GW_SLAVEOPTIONS_APIKEY=.*/TYK_GW_SLAVEOPTIONS_APIKEY=${user_auth}/g" *.env
sed -i "" "s/USER_API_SECRET=.*/USER_API_SECRET=${user_auth}/g" *.env

# 3. Get user id of newly created user using user authentication
uid=$(curlf --header "authorization: $user_auth" \
	    ${db_base}/api/users | jq -r '.users[0].id')

echo "UID= $uid"
# 4. Set password with user authentication
curlf --header "authorization: $user_auth" \
      --data '{"new_password": "supersekret"}' \
      ${db_base}/api/users/${uid}/actions/reset

echo "DONE"
