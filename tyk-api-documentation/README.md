# Tyk API Documentation

The **Tyk API Documentation** is an open api specification with all the endpoints that you can call on the gateway.
## Notes
The current OAS is version 5.3.0 generated from gateway v5.3.0.

The version of Open Api specification used is currently 3.0.3

Currently, we use redocly for linting the OAS. You can install Redocly from (https://github.com/Redocly/redocly-cli)


### How the OAS was generated.

We used the golang library [openapi-go](https://github.com/swaggest/openapi-go) because:
1. It supports producing  OASn for version 3. (Golang doesn't to many libraries to produce OAS three)
2. It is highly customizable, and you can define how you want each field generated.
3. It allows you to write the generation code as functions which is easier to read and maintain

### How to generate the Swagger.yml file

1. Make sure that redocly is installed in your system. You can install Redocly from (https://github.com/Redocly/redocly-cli)
2. Clone the gateway and checkout to the branch [generate-swagger](https://github.com/TykTechnologies/tyk/tree/generate-swagger)
3. cd into the directory called [swagger/cmd](https://github.com/TykTechnologies/tyk/tree/generate-swagger/swagger/cmd).This directory has a make file that contains the rule(the rule is called `generate`) that will be used to generate the swagger.yaml file.
4. Once you are in the directory run the command  `make generate`
5. Once you run this command a file called swagger.yaml will be generated in the same directory which contains all the gateway endpoints.
6. What the  `make generate` do:
      . The generate command is defined as: `rm -f swagger.yaml && go run main.go &&  redocly lint swagger.yaml`
      . It will first delete the previously generated swagger.yaml file it will then generate a new swagger.yaml file, and finally it will use redocly to lint the swagger

### File structure

. In the swagger file we have a file for each OAS tag e.g the cache tag,the key tag etc . If you want to add a new endpoint add it to it specific tag.
. We tehn have a cmd directory that has the main.go file (used to call all tge generation functions), we also have a makefile and the generated swagger.yaml file . 