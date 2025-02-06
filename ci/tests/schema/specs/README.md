# OpenAPI Specification Contract Testing with Portman

To ensure that the schema in our gateway's OpenAPI specification matches our API, we have implemented contract tests
using Portman. Portman leverages Postman collections to automatically generate contract tests from our OpenAPI
specifications.

## What the Contract Tests Cover

1. **Request Body Validation**  
   Verifies that the request body defined in our Swagger schema matches the request body expected by our gateway API.

2. **Response Body Validation**  
   Ensures that the response returned by our gateway API matches the response body defined in our Swagger schema.

3. **Content-Type Validation**  
   Confirms that the content types defined in the request and response schemas in our Swagger documentation match those
   expected and returned by our gateway API.

4. **Header Validation**  
   Validates that the headers sent to or returned by the gateway API are as described in our Swagger documentation.

## Overview of Included Files

- **`config/portman-cli-options.json`**  
  Configures the Portman CLI (similar to `tyk.conf`). It also specifies the location of your `swagger.yml` file. Full
  configuration options can be found [here](https://github.com/apideck-libraries/portman#cli-usage).

- **`config/portmanconfig.json`**  
  [Controls](https://github.com/apideck-libraries/portman#portman-settings) how Portman generates Postman tests. It
  specifies test types and allows overrides for headers or body content in the generated Postman tests.

- **`package.json`**  
  Specifies the Portman version and the command to run Portman, since it uses Node.js.

- **`testdata/populate_gateway_test_data.yaml`**  
  A Venom test file that populates the gateway with necessary test data.

**Generated after running tests:**

- **`gateway.collection.postman.json`**  
  Contains the Portman-generated tests that Newman will execute.

## Running the Tests Locally

To run the tests locally, install...
