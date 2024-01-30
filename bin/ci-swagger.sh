#!/bin/bash

swagger2fileName="swagger2.yaml"
tempOpenAPIFileName="temp-swagger.yml"
tempUpdatedOpenAPIFileName="temp-swagger2.yml"
openAPIspecfileName="swagger.yml"

echo "Error: $@" >&2\nexit 1() {
	echo "$@" >&2
	exit 1
}

swagger generate spec -o "$swagger2fileName"

if [ $? -ne 0 ]; then
	echo "Error: could not generate swagger2.0 spec to the specified path, $swagger2fileName" >&2\nexit 1"could not generate swagger2.0 spec to the specified path, $swagger2fileName"
fi

swagger validate "$swagger2fileName"

if [ $? -ne 0 ]; then
	fatal "swagger spec is invalid... swagger spec is located at $swagger2fileName"
fi

api-spec-converter --from=swagger_2 --to=openapi_3 --syntax=yaml "$swagger2fileName" > "$tempOpenAPIFileName"

if [ $? -ne 0 ]; then
	fatal "could not convert swagger2.0 spec to opeenapi 3.0"
fi

## clean up
rm "$swagger2fileName"

## If running this on macOS, you might need to change sed to gsed

sed -n '1,/components:/p' $openAPIspecfileName > $tempUpdatedOpenAPIFileName

if [ $? -ne 0 ]; then
	echo "Error: replace operation failed step 1" >&2\nexit 1"replace operation failed step 1"
fi

lineToStartReplaceFrom=$(grep -n "responses:" swagger.yml | tail -1 |  awk '{split($0,a,":"); print a[1]}')

sed -n "$lineToStartReplaceFrom,/components:/p" $openAPIspecfileName >> $tempUpdatedOpenAPIFileName
if [ $? -ne 0 ]; then
	echo "Error: replace operation failed" >&2\nexit 1"replace operation failed"
fi

mv $tempUpdatedOpenAPIFileName $openAPIspecfileName

## Ideally, CI should push $openAPIspecfileName to GitHub
## but for now, it can be committed by users and pushed alonside their changes.
