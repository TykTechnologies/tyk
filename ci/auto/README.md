# Automated Testing

This directory hosts the automated testing infrastructure and code. Within each repo there are CI tests which are meant to quickly give feedback on PRs.

# Testing using tyk-automated-tests

Tyk can be deployed in many ways. A deployment is modelled by a compose file. `pro.yml` models a standard Tyk Pro installation.

## Directory structure
```
auto
├── deps.yml           # dependencies that can be reused between deployment models
├── pro.yml            # compose file defining the Tyk components in a Pro deployment
├── {mongo,postgres,..}.yml  # composable compose for 
├── pro.yml            # compose file defining the Tyk components in a Pro deployment
├── pro/               # Tyk configs passed to services in pro.yml
├── confs/             # env var based config settings to override behaviour
├── local-*.env        # Env vars here can be set in the Tyk compose services by setting env_file=<file>
```

The configuration for the tyk components are provided via config files and env variables. The config files are used as the default configuration and behaviour can be overridden using environment variables in `confs/` or `local-*.env`.

# Running tests locally
## Pre-requisites
- docker compose plugin or above (not docker-compose)
- AWS integration account credentials
- dashboard license (`export TYK_DB_LICENSEKEY=`)
- mdcb license

## How to login to AWS ECR
You need an access token and a functional AWS CLI with the sub-account to publish, install, and delete packages in AWS ECR. There is [a note in OneLogin](https://tyk.onelogin.com/notes/108502) with the AWS credentials which have just enough privileges to push and pull from the registry as well as access to logs. Once you have the CLI functional, you can login with:
``` shellsession
% aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin 754489498669.dkr.ecr.eu-central-1.amazonaws.com
```

## Bring up an env
This will bring up a Pro installation using the `master` branch for all components. It does not _build_ the images but relies on `release.yml` in the repo having already pushed the images to ECR. 
``` shellsession
# define an alias for later
$ alias master="env_file=local-mongo44.env docker compose -f pro.yml -f deps.yml -p master --env-file master.env"
$ master up -d
```

## Run tests
In the `tyk-automated-tests` repo, assuming that you are in a virtualenv with all its dependencies installed,
``` shellsession
$ pytest -c pytest_ci.ini [dir or file]
```
