#!/bin/bash

swagger_2_file_name="swagger2.yaml"
temp_openapi_file_name="temp-swagger.yml"
temp_updated_openapi_file_name="temp-swagger2.yml"
openapi_spec_file_name="swagger.yml"

# Define a function to handle fatal errors
fatal() {
	echo "$@" >&2
	exit 1
}

swagger generate spec -o "$swagger2fileName"

if [ $? -ne 0 ]; then
		# Display an error message if swagger2.0 spec generation failed
	fatal "Could not generate swagger2.0 spec to the specified path: $swagger2fileName"
fi

swagger validate "$swagger2fileName"

# Check the exit status of the previous command
if [ $? -ne 0 ]; then
		# Display an error message if swagger spec validation failed
	fatal "Swagger spec is invalid. Swagger spec is located at: $swagger2fileName"
fi

	# Convert swagger2.0 spec to openapi 3.0
	api-spec-converter --from=swagger_2 --to=openapi_3 --syntax=yaml "$swagger_2_file_name" > "$temp_openapi_file_name"

if [ $? -ne 0 ]; then
	fatal "could not convert swagger2.0 spec to opeenapi 3.0"
fi

# Clean up unnecessary files
	rm "$swagger2fileName"

## If running this on macOS, you might need to change sed to gsed

# Extract the top section of the openAPI spec file until the 'components' section and save it to a temporary file
sed -n '1,/components:/p' $openAPIspecfileName > $tempUpdatedOpenAPIFileName

# Check the exit status of the previous command
# Check the exit status of the previous command
# Check the exit status of the previous command
if [ $? -ne 0 ]; then
	fatal "replace operation failed step 1"
fi

lineToStartReplaceFrom=$(grep -n "responses:" swagger.yml | tail -1 |  awk '{split($0,a,":"); print a[1]}')

# Append the section starting from the 'responses' section to the temporary file
sed -n "$lineToStartReplaceFrom,/components:/p" $openAPIspecfileName >> $tempUpdatedOpenAPIFileName
if [ $? -ne 0 ]; then
	fatal "replace operation failed"
fi

mv $tempUpdatedOpenAPIFileName $openAPIspecfileName

# CI ideally pushes $openapi_spec_file_name to GitHub
# However, for now, it can be committed by users and pushed alongside their changes.
