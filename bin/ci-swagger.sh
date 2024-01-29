#!/bin/bash

# Make the script executable
chmod +x bin/ci-swagger.sh

swagger2fileName="swagger2.yaml"
tempOpenAPIFileName="temp-swagger.yml"
tempUpdatedOpenAPIFileName="temp-swagger2.yml"
openAPIspecfileName="swagger.yml"

fatal() {
	echo "$@" >&2
	exit 1
}

swagger generate spec -o "$swagger2fileName" 2>&1 || fatal "Failed to generate swagger 2.0 spec to the specified path, $swagger2fileName"

if [ $? -ne 0 ]; then
	fatal "could not generate swagger2.0 spec to the specified path, $swagger2fileName"
fi

swagger validate "$swagger2fileName" 2>&1 || fatal "Swagger spec is invalid... swagger spec is located at $swagger2fileName"

if [ $? -ne 0 ]; then
	fatal "swagger spec is invalid... swagger spec is located at $swagger2fileName"
fi

api-spec-converter --from=swagger_2 --to=openapi_3 --syntax=yaml "$swagger2fileName" > "$tempOpenAPIFileName" 2>&1 || fatal "Failed to convert swagger 2.0 spec to openapi 3.0"

if [ $? -ne 0 ]; then
	fatal "could not convert swagger2.0 spec to opeenapi 3.0"
fi

# Check if dependencies are available
command -v swagger >/dev/null 2>&1 || fatal "Swagger is not installed or not available in the environment"
command -v api-spec-converter >/dev/null 2>&1 || fatal "api-spec-converter is not installed or not available in the environment"
command -v sed >/dev/null 2>&1 || fatal "sed is not installed or not available in the environment"

## clean up
rm "$swagger2fileName"

## If running this on macOS, you might need to change sed to gsed

sed -n '1,/components:/p' $openAPIspecfileName > $tempUpdatedOpenAPIFileName 2>&1 || fatal "Replace operation failed in step 1"

if [ $? -ne 0 ]; then
	fatal "replace operation failed step 1"
fi

lineToStartReplaceFrom=$(grep -n "responses:" swagger.yml | tail -1 |  awk '{split($0,a,":"); print a[1]}')

sed -n "$lineToStartReplaceFrom,/components:/p" $openAPIspecfileName >> $tempUpdatedOpenAPIFileName 2>&1 || fatal "Replace operation failed"
if [ $? -ne 0 ]; then
	fatal "replace operation failed"
fi

mv $tempUpdatedOpenAPIFileName $openAPIspecfileName

## Ideally, CI should push $openAPIspecfileName to GitHub
## but for now, it can be committed by users and pushed alonside their changes.
