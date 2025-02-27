#!/bin/bash
# The main schema file doesn't have 'additionalProperties' set. This is because
# there's an expectation of a downgrade hitting a schema validation step.
#
# For development, we want this property set to validate the JSON schema
# against the implementation and expose uncovered fields.


input="x-tyk-api-gateway.json"
output="x-tyk-api-gateway.strict.json"

cat $input \
	| jq -r '(.additionalProperties = false) | (.definitions |= map_values(. + {"additionalProperties": false}))' \
	| jq -r '.definitions["X-Tyk-EventHandlers"].additionalProperties = true' \
	| jq -r '.definitions["X-Tyk-Webhook-With-ID"].additionalProperties = true' \
	| jq -r '.definitions["X-Tyk-Webhook-Without-ID"].additionalProperties = true' \
	| jq -r '.definitions["X-Tyk-JSVMEvent"].additionalProperties = true' \
	| jq -r '.definitions["X-Tyk-LogEvent"].additionalProperties = true' \
	> $output
