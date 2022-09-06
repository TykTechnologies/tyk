# this document outlines the architecture for the GraphQL Engine

## requirements

- have multiple data sources to resolve an object (e.g. pass an ID to two functions and merge the result, similar to map reduce)
- resolves @defer: splits query into multiple serially executable statements, each emitting a response object to the client
- resolves @stream: splits query at the @stream directive to stream a list of objects to the client
- resolves __type & __schema queries
- injects variables correctly into GraphQL sub queries in case multiple GraphQL queries will be assembled
- can map from data source response objects to correct GraphQL object structure
- can map between upstream GraphQL Enums and downstream GraphQL Enums
- can filter results from upstream data source based on custom plugin/middleware or predefined rules
- resolves child data sources inside an array concurrently
- can pass custom configuration to individual data sources, e.g. setting Headers for HTTP based data sources
- can pass request data from the downstream client to an upstream server (e.g. Headers)
- can have static data sources
- can have streaming data sources, e.g. RabbitMQ, Kafka, NATS
- can have GraphQL and non GraphQL data sources nested into each other
- can have multiple root level fields attached to the same data source
- returns an internal error in case the error is not recoverable
- returns an external error to tell the user about the error
- might return both an internal as well as an external error
- there should be triggers which are similar to data sources in that they trigger a subscription but don't resolve it themselves, instead they hand over the resolving to a data source (this is useful e.g. when you want to trigger a subscription from mutations but the mutations don't contain the data to resolve the subscription so from the trigger a query needs to be fired to resolve the subscription)
- for subscriptions with a trigger there should be an idempotent mechanism (configurable) to ensure that each trigger only fires one event in case that's the desired behaviour (e.g. polling an upstream but only emit changes)
- object path selector for arguments should make use of existing mappings (planning)
- can skip data source invocation based on conditions (e.g. missing field on parent object)
- return number of nodes in response

## implemented in execution

- resolves operations containing unions & interfaces
- resolves flat queries/mutations
- can define __typename for individual objects returned by data sources (users should be able to set the __typename using a middleware/plugin or predefined rules)

## implemented in planning

query:
resolve() -> client

subscription:
for {
    resolve() -> client
}

stream:
resolveUser() -> client
for i := range user.friends {
    resolveFriend(i) -> client
    resolvePet(friend) -> client
}


```go
package resolving
type Resolver interface {
	Resolve(ctx context.Context,userID string, config, input []byte) (output []byte, err error)
}
```

QueryPlan:
    ResolveOneUser()
    ResolveUserFriends()
    ResolveManyPets()