# Tyk API Documentation

The **Tyk API Documentation** is an OpenAPI specification that outlines the endpoints you can call on the gateway.

## Notes

The current OAS version is **v3.0.3**, generated from gateway **v5.6.0**.

We are currently using OpenAPI Specification version **v3.0.3**.

For linting the OAS, we use Redocly. You can install Redocly from [here](https://github.com/Redocly/redocly-cli).

## How the OAS was generated

We used the Go library [openapi-go](https://github.com/swaggest/openapi-go) because:
1. It supports generating OAS for version **v3.0.3** (there are not many Go libraries that produce OAS v3.0.3).
2. It is highly customizable, allowing you to define how each field is generated.
3. It lets you write the generation code as functions, making it easier to read and maintain.

## How to generate the Swagger.yml file

1. Ensure that Redocly is installed on your system. You can install Redocly from [here](https://github.com/Redocly/redocly-cli).
2. Clone the gateway repository and check out the branch [generate-swagger](https://github.com/TykTechnologies/tyk/tree/generate-swagger).
3. Navigate to the directory [swagger/cmd](https://github.com/TykTechnologies/tyk/tree/generate-swagger/swagger/cmd). This directory contains a Makefile with a rule (`generate`) used to generate the swagger.yml file.
4. Run the command `make generate` in this directory.
5. After running this command, a `swagger.yml` file containing all the gateway endpoints will be generated in the same directory.
6. What the `make generate` command does:
   - The command is defined as: `rm -f swagger.yml && go run main.go && redocly lint swagger.yml`.
   - It first removes the existing `swagger.yml` file (if any), generates a new `swagger.yml` file, and finally lints the file using Redocly.

## File Structure

1. In the Swagger folder, there is a file for each OAS tag (e.g., cache tag, key tag, etc.). If you want to add a new endpoint, add it to its specific tag.
2. The `cmd` directory contains the `main.go` file (used to call all the generation functions), a Makefile, and the generated `swagger.yml` file.
