[![Build Status](https://travis-ci.org/lonelycode/tyk.svg?branch=master)](https://travis-ci.org/lonelycode/tyk) [![Coverage Status](https://coveralls.io/repos/lonelycode/tyk/badge.png?branch=master)](https://coveralls.io/r/lonelycode/tyk?branch=master)

# Tyk API Gateway ##

Tyk is a lightweight, open source API Gateway and enables you to control who accesses your API, when they access it and how they access it. Tyk will
also record detailed analytics on how your users are interacting with your API and when things go wrong.

***

## What is an API Gateway? ##

An API Gateway sits in front of your application(s) and manages the heavy lifting of authorisation, access control and throughput limiting to your services. Ideally, 
it should mean that you can focus on creating services instead of implementing management infrastructure. For example if you have written a really awesome web service
that provides geolocation data for all the cats in NYC, and you want to make it public, integrating an API gateway is a faster, more secure route that writing your own 
authorisation middleware.

## Key Features of Tyk ##

Tyk offers powerful, yet lightweight features that allow fine gained control over your API ecosystem.

* **RESTFul API** - Full programatic access to the internals makes it easy to manage your API users, keys and Api Configuration from within your systems
* **Multiple access protocols** - Out of the box, Tyk supports Token-based, HMAC Signed, Basic Auth and Keyless access methods
* **Rate Limiting** - Easily rate limit your API users, rate limiting is granular and can be applied on a per-key basis
* **Quotas** - Enforce usage quotas on users to manage capacity or charge for tiered access
* **Granular Access Control** - Grant api access on a version by version basis, grant keys access to multiple API's or just a single version
* **Key Expiry** - Control how long keys are valid for
* **API Versioning** - API Versions can be easily set and deprecated at a specific time and date
* **Blacklist/Whitelist/Ignored endpoint access** - Enforce strict security models on a version-by-version basis to your access points
* **Analytics logging** - Record detailed usage data on who is using your API's (raw data only)
* **Webhooks** - Trigger webhooks against events such as Quota Violations and Authentication failures
* **IP Whitelisting** - Block access to non-trusted IP addresses for more secure interactions
* **Zero downtime restarts** - Tyk configurations can be altered dynamically and the service restarted without affecting any active request


Tyk is written in Go, which makes it fast and easy to set up. Its only dependencies are a Mongo database (for analytics) and Redis, 
though it can be deployed without either (not recommended).

## Why? ##

Tyk was built because other open source API Gateways in the market come with dependencies and bloat, attempting to be too many things to too many people. tyk is focused,
simple and does one thing well - protecting your API from unauthorised access.

## Documentation ##

All the documentation can be found on our main site at http://tyk.io/

## License ##

Tyk is released under the MPL v2.0 please see the LICENSE.md file for a full version of the license.

## Contribute / Build ##

To get started contributing, clone the repo to your local go workspace, change into the new tyk directory and run `go get`, this should retrieve all the dependencies.

We are working to increase test coverage of features, currently the majority of auth methods and middleware are tested, however it could always be better.

Any changes that are submitted with a pull request should come with a test and be in a separate branch. Basically, use this checklist:

- Do your changes have tests?
- Have you run the tests?
- Did they pass?
- Have you written a test for your feature?
- Does it pass after merge?

If you can answer yes to all of the above, feel free to submit a pull request :-)

## Roadmap

To coordinate development and be completely transparent as to where the project is going, the version roadmap for the next version, as well as proposed features
and adopted proposals can be viewed on our public Trello board:

[https://trello.com/b/59d5kAZ5/tyk-api-gateway-roadmap](https://trello.com/b/59d5kAZ5/tyk-api-gateway-roadmap)

Any proposals can be made in the Github issue tracker, proposals that are adopted will be placed into the trello and then moved according to their status.

### A note on the tests

Currently in order for tests to pass, a redis host is required. We know, this is terrible and should be handled with an interface, and it is, however
in the current version there is a hard requirement for the application to have its default memory setup to use redis as part of a deployment, this is
to make it easier to install the application for the end-user. Future versions will work around this, or we may drop the memory requirement.

The simplest way to get the tests to run is to install local redis, or (what I do) have a vagrant instance that is running redis, then you can just `vagrant up`
when you need redis and kill it later. Just make sure you are forwarding the default ports 1:1.

### Dev versus stable

The master branch is NOT the stable releases, check the tags for stable releases that can be patched, please se the CHANGELOG for breaking changes or to see how things stand.

Documentation is currently valid for the 1.1 release.
