# OpenAPI Specification Contract Testing with Portman

To ensure that the schema in our gateway's OpenAPI specification matches our API, we have implemented contract tests using Portman. Portman leverages Postman collections to automatically generate contract tests from our OpenAPI specifications.

## What the Contract Tests Are Testing:

1. **Request Body Validation**: Verifying that the request body defined in our Swagger schema matches the request body expected by our gateway API.

2. **Response Body Validation**: Ensuring that the response returned by our gateway API matches the response body defined in our Swagger schema.

3. **Content-Type Validation**: Confirming that the content types defined in the request and response schemas in our Swagger documentation match those expected and returned by our gateway API.

4. **Header Validation**: Validating that the headers sent to or returned by the gateway API are as described in our Swagger documentation.

## Overview of the Included Files

1. **config/portman-cli-options.json**: This file sets the configuration for running the Portman CLI (similar to `tyk.conf`). It also specifies the location of your `swagger.yml` file. Full configuration options can be found [here](https://github.com/apideck-libraries/portman#cli-usage).

2. **config/portmanconfig.json**: [This file controls](https://github.com/apideck-libraries/portman#portman-settings) the content and how Portman generates the Postman tests. It specifies the types of tests to generate and any values to override in the generated tests. For example, to override headers or body content in the generated Postman tests, declare the overriding values in this file.

3. **package.json**: Since Portman uses Node.js, this file specifies the Portman version to install and the command to run Portman.

4. **testdata/populate_gateway_test_data.yaml**: A Venom test file that populates the gateway with data needed for the tests.

**The following file is generated after running the tests:**

- **gateway.collection.postman.json**: Contains the tests generated by Portman that Newman will execute.

## How to Run It Locally

To run the tests locally, install the following:

1. [Venom](https://github.com/ovh/venom): Used to populate data needed for the Portman tests.

2. [Portman](https://github.com/apideck-libraries/portman): Generates the contract tests from the Swagger file and converts them into Postman tests.

3. [Newman](https://github.com/postmanlabs/newman): A Postman CLI tool needed to run the contract tests.

Once these dependencies are installed, navigate to the `ci/tests/specs` directory and create a `.env` file using .env.example as template. Inside the `.env` file, add:

```bash
PORTMAN_API_Key=<Your Tyk Gateway secret>
```

After adding the `PORTMAN_API_Key`, run the `task` command from ci/tests/specs directory to run a gateway instance and execute portman tests.

You can then stop the gateway instance by running `task down` command from the ci/tests/specs directory.

## How It Is Run on the CI

The GitHub Action used to run these tests is `swagger-contract-tests.yml`.

- In the CI environment, we launch a live gateway using the using th image created by release.yml GitHub action on every pull request.

- After that, we run the task `task tests`, which uses Portman to generate and execute all the Swagger contract tests.
