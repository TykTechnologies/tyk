# Contributing to Tyk

**First**: if you're unsure or afraid of anything, just ask or submit the issue or pull request anyways. You won't be yelled at for giving your best effort. The worst that can happen is that you'll be politely asked to change something. We appreciate any sort of contributions, and don't want a wall of rules to get in the way of that.

However, for those individuals who want a bit more guidance on the best way to contribute to the project, read on. This document will cover what we're looking for. By addressing all the points we're looking for, it raises the chances we can quickly merge or address your contributions.

## Filing issues

If you have a question about Tyk or have a problem using it, please
start with the GitHub search and our [community forum](https://community.tyk.io). If that doesn't answer your questions, or if you think you found a bug, please [file an
issue](https://github.com/TykTechnologies/tyk/issues/new).

## How to become a contributor and submit your own code

### Contributor License Agreements

We'd love to accept your patches! Before we can take them, we have to jump a couple of legal hurdles.

The Tyk CLA [must be signed](https://github.com/TykTechnologies/tyk/blob/master/CLA.md) by all contributors. You will be automatically asked to sign CLA once PR will be created.

Once you are CLA'ed, we'll be able to accept your pull requests. For any issues that you face during this process, please create a GitHub issue explaining the problem and we will help get it sorted out.

***NOTE***: Only original source code from you and other people that have
signed the CLA can be accepted into the repository. This policy does not
apply to [vendor](vendor/).

### Finding Things That Need Help

If you're new to the project and want to help, but don't know where to start,
we have a semi-curated list of issues that have should not need deep knowledge
of the system.  [Have a look and see if anything sounds
interesting](https://github.com/TykTechnologies/tyk/issues?q=is%3Aopen+is%3Aissue+label%3Ahelp-wanted).

Alternatively, read some of the [many docs on the system](https://tyk.io/docs/getting-started/), and pick a component that seems
interesting.  Start with `main()` and read
until you find something you want to fix.  The best way to learn is to hack!
There's always code that can be clarified and variables or functions that can
be renamed or commented.

### `master` is unstable

We will do our best to keep master in good shape, with tests passing at all times. But in order to move fast, we will make API changes that your application might not be compatible with. We will do our best to communicate these changes and version appropriately so you can lock into a specific version if need be. For stable releases check our tags and `stable` branch, which contains our latest stable release.


### Contributing A Patch

If you're working on an existing issue, such as one of the `help-wanted` ones
above, simply respond to the issue and express interest in working on it.  This
helps other people know that the issue is active, and hopefully prevents
duplicated efforts.

If you want to work on a new idea of relatively small scope:

1. Submit an issue describing your proposed change to the repo in question.
1. The repo owners will respond to your issue promptly.
1. Clone the repo, develop, and test your changes.
1. Submit a pull request.
1. If your proposed change is accepted, and you haven't already done so, sign a
   Contributor License Agreement (see details above).

If you want to work on a bigger idea, we **strongly** recommend that you start with
some bugs or smaller features. It is always better to discuss your idea with our team first, before implementing it.

### Downloading the project
You need to clone Tyk from GitHub to your GOPATH folder, or alternatively you can run `go get -d github.com/TykTechnologies/tyk` which automatically downloads project to the right path.

### Building the project
You need to have working Go environment: see [golang.org](https://golang.org/doc/code.html) for more info on how Go works with code.

To build and test Tyk use built-in `go` commands: `go build` and `go test -v`. If you want to just test a subset of the project, you can pass the `-run` argument with the name of the test. Note that logs are hidden by default when running the tests, which you can override by setting `TYK_LOGLEVEL=info`.

Currently, in order for tests to pass, a **Redis host is required**. We know, this is terrible and should be handled with an interface, and it is, however in the current version there is a hard requirement for the application to have its default memory setup to use Redis as part of a deployment, this is to make it easier to install the application for the end-user. Future versions will work around this, or we may drop the memory requirement. The simplest way to run Redis is to use official Docker image [https://hub.docker.com/_/redis/](https://hub.docker.com/_/redis/)

#### Using Task Commands

In addition to the standard Go commands, we also provide [Task](https://taskfile.dev/) commands to simplify the setup and local dev process. 
If you haven't installed Task yet, please follow the [installation instructions](https://taskfile.dev/installation).

Once Task is installed, you can use the following commands:

```shell
task setup   # Sets up the project depdendencies, including pre-commit hooks
task test:integration    # Runs the tests
```

### Geo IP features
This product utilises GeoLite2 data created by MaxMind, available from [http://www.maxmind.com](http://www.maxmind.com).
