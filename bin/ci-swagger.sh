#!/bin/bash

swagger2fileName="swagger2.yaml"
tempOpenAPIFileName="temp-swagger.yml"
tempUpdatedOpenAPIFileName="temp-swagger2.yml"
openAPIspecfileName="swagger.yml"

fatal() {
	echo "$@" >&2
	exit 1
}

swagger generate spec -o "swagger2.yaml"

if [ $? -ne 0 ]; then
	fatal "could not generate swagger2.0 spec to the specified path, $swagger2fileName"
fi

swagger validate "$swagger2fileName"


	fatal "swagger spec is invalid... swagger spec is located at $swagger2fileName"
fi

api-spec-converter --from=swagger_2 --to=openapi_3 --syntax=yaml "swagger2.yaml" > "temp-swagger.yml"

if [ $? -ne 0 ]; then
	fatal "could not convert swagger2.0 spec to opeenapi 3.0"
fi

## clean up
rm "$swagger2fileName"

## If running this on macOS, you might need to change sed to gsed

sed -n '1,/components:/p' $tempOpenAPIFileName > $tempUpdatedOpenAPIFileName

if [ $? -ne 0 ]; then
	fatal "replace operation failed step 1"
fi

lineToStartReplaceFrom=$(grep -n "responses:" swagger.yml | tail -1 |  awk '{split($0,a,":"); print a[1]}')

sed -n "$lineToStartReplaceFrom,/components:/p" $tempOpenAPIFileName >> $tempUpdatedOpenAPIFileName
if [ $? -ne 0 ]; then
	fatal "replace operation failed"
fi

mv $tempUpdatedOpenAPIFileName $openAPIspecfileName

## Ideally, CI should push $openAPIspecfileName to GitHub
## but for now, it can be committed by users and pushed alonside their changes.
