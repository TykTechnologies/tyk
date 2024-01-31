#!/bin/bash

swagger2fileName="swagger2.yaml"
tempOpenAPIFileName="temp-swagger.yml"
tempUpdatedOpenAPIFileName="temp-swagger2.yml"
openAPIspecfileName="swagger.yml"

fatal() {
	echo "$@" >&2
	exit 1
}

swagger generate spec -o "$swagger2fileName" 2>> ci/tests/error_logs.txt

if [ $? -ne 0 ]; then
	echo "Error: could not generate swagger2.0 spec to the specified path, $swagger2fileName" >> ci/tests/error_logs.txt
fi

swagger validate "$swagger2fileName"

if [ $? -ne 0 ]; then
	echo "Error: swagger spec is invalid... swagger spec is located at $swagger2fileName" >> ci/tests/error_logs.txt
fi

api-spec-converter --from=swagger_2 --to=openapi_3 --syntax=yaml "$swagger2fileName" > "$tempOpenAPIFileName"

if [ $? -ne 0 ]; then
	echo "Error: could not convert swagger2.0 spec to openapi 3.0" >> ci/tests/error_logs.txt
fi

## clean up
rm "$swagger2fileName"

## If running this on macOS, you might need to change sed to gsed

sed -n '1,/components:/p' $openAPIspecfileName >> $tempUpdatedOpenAPIFileName 2>> ci/tests/error_logs.txt

if [ $? -ne 0 ]; then
	echo "Error: replace operation failed step 1" >> ci/tests/error_logs.txt
fi

lineToStartReplaceFrom=$(grep -n "responses:" swagger.yml | tail -1 |  awk '{split($0,a,":"); print a[1]} 2>> ci/tests/error_logs.txt')

sed -n "$lineToStartReplaceFrom,/components:/p" $openAPIspecfileName >> $tempUpdatedOpenAPIFileName
if [ $? -ne 0 ]; then
	echo "Error: replace operation failed" >> ci/tests/error_logs.txt
fi

mv $tempUpdatedOpenAPIFileName $openAPIspecfileName

## Clean up
echo "Cleanup: Removing $swagger2fileName" >> ci/tests/error_logs.txt
rm $swagger2fileName
