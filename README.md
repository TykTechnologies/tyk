# Tyk API Gateway

<!-- [![Build Status](https://travis-ci.org/TykTechnologies/tyk.svg?branch=master)](https://travis-ci.org/TykTechnologies/tyk) -->
[![Go Report Card](https://goreportcard.com/badge/github.com/TykTechnologies/tyk)](https://goreportcard.com/report/github.com/TykTechnologies/tyk)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FTykTechnologies%2Ftyk.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FTykTechnologies%2Ftyk?ref=badge_shield)

Tyk is an open source Enterprise API Gateway, supporting REST, GraphQL, TCP and gRPC protocols. 

Tyk Gateway is provided ‘Batteries-included’, with no feature lockout. Enabling your organization to control who accesses your APIs, when they access, and how they access it. 

Tyk Technologies uses the same API Gateway for all it’s applications. Protecting, securing, and processing APIs for thousands of organizations and businesses around the world. Ideal for Open Banking, building software in the clouds as well as exposing APIs to teams, partners & consumers. 

Built from the ground up to be the fastest API gateway on the planet. It does not depend on a legacy proxy underneath. It has no 3rd party dependencies aside from [Redis](https://github.com/redis/redis) for distributed rate-limiting and token storage. Tyk Gateway can also be deployed as part of a larger Full Lifecycle API Management platform [Tyk Self-Managed](https://tyk.io/features/dashboard/) which also includes Management Control Plane, Dashboard GUI and Developer Portal.

![image](https://user-images.githubusercontent.com/14009/109156132-8ae9d980-7781-11eb-88d7-0b77c753a9ca.png)



# Open Source API Gateway Features

**Use any protocol:** REST, SOAP, GraphQL, gRPC, and TCP.

**Industry Standard Authentication**: OIDC, JWT, bearer Tokens, Basic Auth, Client Certificates and more.

**Open API Standards**: Import your Swagger and OAS2/3 documents to scaffold APIs in Tyk.

**Ultra performant:** Low latency, and thousands of rps with just a single CPU, horizontally and vertically scalable.

**Content mediation**: Transform all the things, from request or response headers to converting between SOAP and GraphQL. 

**Extensible Plugin Architecture**: Customize Tyk’s middleware chain by writing plugins in your language of choice - from Python to Javascript to Go, or any language which supports gRPC.


**Rate Limiting & Quotas:** Protect your upstreams from becoming overloaded and/or apply limits for each consumer. 

**API Versioning** - API Versions can be easily set and deprecated at a specific time and date.

**Granular Access Control** - Grant access to one or more APIs on a per version and operation basis.

**Blocklist/Allowlist/Ignored endpoint access** - Enforce strict security models on a version-by-version basis to your access points.

**Analytics logging** - Record detailed usage data on who is using your API's (raw data only)

**CORS** - Enable [CORS](https://tyk.io/docs/tyk-apis/tyk-gateway-api/api-definition-objects/cors/) for certain APIs so users can make browser-based requests

**Webhooks** - Trigger webhooks against events such as Quota Violations and Authentication failures

**IP AllowListing** - Block access to non-trusted IP addresses for more secure interactions

**Hitless reloads** - Tyk configurations can be altered dynamically and the service restarted without affecting any active request

**Kubernetes native declarative API:** using Open Source [Tyk Operator](https://github.com/TykTechnologies/tyk-operator) (more info in OSS section)

_And everything else you expect from a Cloud Native API Gateway_




# Quick Start on your platform

Get Started today with Tyk Gateway (standalone) 

Install 

1. [Docker](https://tyk.io/docs/tyk-oss/ce-docker/) (Recommended method)
2. [ Kubernetes-Native  ](https://github.com/TykTechnologies/tyk-oss-k8s-deployment)
3. [Kubernetes-Helm](https://github.com/TykTechnologies/tyk-helm-chart#install-tyk-community-edition)
4. [Ansible](https://tyk.io/docs/tyk-oss/ce-ansible/)
5. [Red Hat](https://tyk.io/docs/tyk-oss/ce-redhat/)  
6. [Ubuntu](https://tyk.io/docs/tyk-oss/ce-ubuntu/)  
7. [CentOS](https://tyk.io/docs/tyk-oss/ce-centos/) 
8. Compile from Source (see instructions below)

# Compiling Tyk Gateway

Compile from Source

```
git clone https://github.com/TykTechnologies/tyk
go build
```


Go version 1.12 is required to build `master`, the current development version. Tyk is officially supported on `linux/amd64`, `linux/i386` and `linux/arm64`.

Tests are run against both Go versions 1.12, 1.13, 1.14 and 1.15, however at present, only Go 1.12 is officially supported.
In order to run tests locally use the following command:

```
go test ./...
```

Note that tests require Redis to be running on the same machine (default port).

In order to write your own test pls use this guide [https://github.com/TykTechnologies/tyk/blob/master/TESTING.md](https://github.com/TykTechnologies/tyk/blob/master/TESTING.md)

# Contributing

For more information about contributing PRs and issues, see [CONTRIBUTING.md](https://github.com/TykTechnologies/tyk/blob/master/CONTRIBUTING.md).


# Tyk OSS Integrations

Tyk Technologies maintains other Open Source Software which can be used in conjunction with Tyk API Gateway:

[Tyk Pump](https://github.com/TykTechnologies/tyk-pump) - Pluggable analytics purger to move Analytics generated by your Tyk nodes to any back-end.

[Tyk Operator](https://github.com/TykTechnologies/tyk-operator) - Brings API Management capabilities to Kubernetes. Configure Ingress, APIs, Security Policies, Authentication, Authorization, Mediation and more - all using Custom Resources and Kubernetes Native primitives

[Tyk Identity Broker](https://github.com/TykTechnologies/tyk-identity-broker) - Tyk Authentication Proxy for third-party login

[Tyk Sync ](https://github.com/TykTechnologies/tyk-sync)- Command line tool and library to manage and synchronise a Tyk installation with your version control system (VCS).

[Tyk Mserv](https://github.com/TykTechnologies/mserv) - Asset Server and gRPC host

![image](https://user-images.githubusercontent.com/14009/112309048-ea210800-8cb3-11eb-8e8e-dceb4cae4cad.png)

# Documentation

All the documentation for Tyk Gateway and other OSS can be found at [https://tyk.io/docs/tyk-oss-gateway/](https://tyk.io/docs/tyk-oss-gateway/)


# Community



*   [Tyk Community Board](https://community.tyk.io) - Technical support from the Tyk Community
*   [Write a GitHub Issue](https://github.com/TykTechnologies/tyk/issues/new/choose) - Feature requests & bug reports welcome
*   [Technical blog](https://tyk.io/api-expertise/blog/) - Tyk announcements and updates
*   [Newsletters ](https://pages.tyk.io/newsletter)- Subscribe to our GraphQL & API newsletters
*   If you are using Tyk give us a star ⭐️  


# Open Source License

Tyk is released under the MPL v2.0; please see [LICENSE.md](https://github.com/TykTechnologies/tyk/blob/master/LICENSE.md) for a full version of the license.

![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FTykTechnologies%2Ftyk.svg?type=large)
