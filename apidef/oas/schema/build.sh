#!/bin/bash
# The main schema file doesn't have 'additionalProperties' set. This is because
# there's an expectation of a downgrade hitting a schema validation step.
#
# For development, we want this property set to validate the JSON schema
# against the implementation and expose uncovered fields.
jq -r '(.additionalProperties = false) | (.definitions |= map_values(. + {"additionalProperties": false}))' x-tyk-api-gateway.json > x-tyk-api-gateway.strict.json
