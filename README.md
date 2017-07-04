# Tyk API Gateway

[![Build Status](https://travis-ci.org/TykTechnologies/tyk.svg?branch=master)](https://travis-ci.org/TykTechnologies/tyk)
[![Go Report Card](https://goreportcard.com/badge/github.com/TykTechnologies/tyk)](https://goreportcard.com/report/github.com/TykTechnologies/tyk)

Tyk is a lightweight, open source API Gateway and Management Platform enables you to control who accesses your API, when they access it and how they access it. Tyk will
also record detailed analytics on how your users are interacting with your API and when things go wrong.

Go version 1.7 or later is required to build. Tyk is officially
supported on `linux/amd64`, `linux/i386` and `linux/arm64`.

## What is an API Gateway?

An API Gateway sits in front of your application(s) and manages the heavy lifting of authorisation, access control and throughput limiting to your services. Ideally, 
it should mean that you can focus on creating services instead of implementing management infrastructure. For example if you have written a really awesome web service
that provides geolocation data for all the cats in NYC, and you want to make it public, integrating an API gateway is a faster, more secure route than writing your own 
authorisation middleware.

## Key Features of Tyk

Tyk offers powerful, yet lightweight features that allow fine grained control over your API ecosystem.

* **RESTFul API** - Full programmatic access to the internals makes it easy to manage your API users, keys and Api Configuration from within your systems
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

## Why?

Tyk was built because other open source API Gateways in the market come with dependencies and bloat, attempting to be too many things to too many people. Tyk is focused,
simple and does one thing well - protecting your API from unauthorised access.

### Documentation

All the documentation can be found at http://tyk.io/docs/.

### License

Tyk is released under the MPL v2.0; please see [LICENSE.md] for a full version of the license.

### Contributing

For more information about contributing PRs and issues, see [CONTRIBUTING.md].

### Roadmap

To coordinate development and be completely transparent as to where the project is going, the version roadmap for the next version, as well as proposed features
and adopted proposals can be viewed on our public [Trello board](https://trello.com/b/59d5kAZ5/tyk-api-gateway-roadmap).

Any proposals can be made in the Github issue tracker. Proposals that are adopted will be placed into trello and then moved according to their status.
