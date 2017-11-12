# Customized Tyk API Gateway ##
This is actually customized version of https://github.com/TykTechnologies/tyk
 for Gett. The reason we have it is that currently original tyk gateway doesn't support newrelic integration.
The solution was taken from https://github.com/nebolsin/tyk/tree/wtf
## Usage:

Build an image with
```
docker build . -t organization/image_repository_name
docker push organization/image_repository_name
```
In your gateway service Dockerfile use it as base image:
```bash
FROM organization/image_repository_name
```
Don't forget to set starting CMD and your own tyk.conf file.
You can find example here https://github.com/gtforge/b2b_gateway
