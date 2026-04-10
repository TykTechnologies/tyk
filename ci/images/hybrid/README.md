## Usage
Please refer to the official tyk.io docs for information about how to run this Multi-Cloud docker image:
[Tyk Docs - Multi Cloud Usage](https://tyk.io/docs/get-started/with-tyk-multi-cloud/tutorials/install-multicloud-gateway/)

## What's different about this Image and the Gateway Image?
The main differences between the Docker Hybrid image and the Docker Gateway Image are the following:

### Includes Redis Server
This Hybrid image runs with an integrated Redis Server.  You can see the dependency for the service installed in the Dockerfile, and then you can see the service being started in the entrypoint.sh file.  

This is not optional.  Should you choose to run your own Redis configuration, you will need to run the Gateway Image instead, and tweak the `tyk.conf` to run in multi-cloud.

### Includes Nginx Server
This Hybrid image runs with an included Nginx server.

In order to disable it, just add an environment variable 
`-e DISABLENGINX=1`
If you are running multi-cloud through the start.sh script, you will need to modify it there.

### Tyk.conf
Of course, the `tyk.conf` included in this repo will already be setup to connect as a slave node to the MDCB( Multi Data Center Bridge) instance.  You shouldn't need to make any changes to this file.