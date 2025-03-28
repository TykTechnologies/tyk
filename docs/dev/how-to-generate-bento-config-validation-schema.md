# How to generate Bento Configuration Validator Schema for Tyk

There is a script named `generate_bento_config_schema` under `apidef/streams/bento/schema` folder in Tyk GW repository. 
This script generates a JSON schema for the input & output resources that Tyk supports. There are two ways to run this script.

## Running the script directly

Simply, `go run generate_bento_config_schema.go` command in the source code folder. 
It'll generate a file named `bento-config-schema.json` in the current working folder. 
You can also set an output path via `-output <string>` parameter.

This is useful for development purposes.

## Running via task runner

Simply run the following command under Tyk GW repository’s root folder.

```shell
task generate-bento-config-validator-schema
```

The task will automatically update `apidef/streams/bento/schema/bento-config-schema.json` file. 
This should be done after upgrading Bento in Tyk GW.

## How to add a new input & output resources

**1-** Import the related component for its side effects.

For example if you want to produce a JSON schema that supports redis component, 
you can import it like the following:

```go
 _ "http://github.com/warpstreamlabs/bento/public/components/redis"`
```

**2-** Add the component name to `supportedSources` slice. You should know that some 
components exposes different input/output sources.

For example, `components/kafka` exposes `kafka` and `kafka_franz`. You need to dig into the Bento's codebase to understand 
which input/output is exposed by a component.

See the list of components: https://github.com/warpstreamlabs/bento/tree/main/public/components

Importing all components was not preferred because it results in generating a gigantic JSON schema, and it’s too hard to 
navigate in that file and debug possible issues. 