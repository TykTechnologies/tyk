#!/bin/bash

swagger2fileName="swagger2.yaml"
openAPIspecfileName="gateway-swagger.yaml"

fatal() {
	echo "$@" >&2
	exit 1
}

swagger generate spec -o "$swagger2fileName"

if [ $? -ne 0 ]; then
	fatal "could not generate swagger2.0 spec to the specified path, $swagger2fileName"
fi

swagger validate "$swagger2fileName"

if [ $? -ne 0 ]; then
	fatal "swagger spec is invalid... swagger spec is located at $swagger2fileName"
fi

api-spec-converter --from=swagger_2 --to=openapi_3 --syntax=yaml "$swagger2fileName" > "$openAPIspecfileName"

if [ $? -ne 0 ]; then
	fatal "could not convert swagger2.0 spec to opeenapi 3.0"
fi

## clean up
rm "$swagger2fileName"

## Ideally, CI should push $openAPIspecfileName to GitHub
## but for now, it can be committed by users and pushed alonside their changes.
