# Requirements:
#### Install dependencies:
```bash
make install-k8s-tools
```

# How to create a kind (a nice tool to simulate a k8s on local env) cluster:
```bash
make create-kind-cluster
```
* the cluster will be created with the name `kind`, set CLUSTER_NAME to change the name of the cluster.

# How to delete a kind cluster:
```bash
make delete-kind-cluster
```

# How to install the required dependencies in the kind cluster
### Create the namespace
```bash
kubectl create namespace tyk
```

### Install the required dependencies

#### - Redis

For Redis we have two options. We can either use a custom "simple redis" chart
that doesn't require any setup as it's already configured to work with tyk default configuration options.
```bash
helm install redis tyk-helm/simple-mongo -n tyk
```

Or we can use the official Redis chart and configure it to work with Tyk. 
```bash
helm upgrade tyk-redis oci://registry-1.docker.io/bitnamicharts/redis -n tyk --create-namespace --install --version 19.0.2
```

After installation, you can follow the notes from the cli output to get connection details and password.

As this installation is not pre-configured to work with Tyk, we need to set global.redis.pass=$REDIS_PASSWORD in the values.yaml file.
####

#### - MongoDB

For MongoDB we have two options. We can either use a custom "simple mongo" chart
that doesn't require any setup as it's already configured to work with tyk default configuration options.

```bash
helm install mongo tyk-helm/simple-mongodb -n tyk
```

Or we can use the official MongoDB chart and configure it to work with Tyk. 
NOTE: there is no official MongoDB chart that works on M1 Macs, so you will need to use the simple-mongo chart in this case.
Another alternative is to use a global mongo deployment.
```bash
helm install tyk-mongo bitnami/mongodb --set "replicaSet.enabled=true" -n tyk --version 15.1.3
```

In this case we need to set global.mongo.mongoURL and global.storageType to the correct values in the values.yaml file.
For the mongoURL you should replace the password in the connection string with the MONGODB_ROOT_PASSWORD obtained
from the installation output notes.

As an intermediary step we can run:
```bash
make generate-k8s-value-files
```

This will create three files in the k8s folder for each of the variants of Tyk:
- ossValues.yaml
- dataPlaneValues.yaml
- controlPlaneValues.yaml

After the minimal setup of dependencies the next step is to install the Tyk charts.
Should you want to play with your configuration, you can modify the values.yaml files and install the charts with the following commands:

```bash
helm install tyk-oss tyk-helm/tyk-oss -n tyk --create-namespace -f ossValues.yaml
```

```bash
helm install tyk-control-plane tyk-helm/tyk-control-plane -n tyk --create-namespace -f dataPlaneValues.yaml
```


