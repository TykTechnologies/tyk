# Requirements:
#### - Kubectl
```bash
$ brew install kubectl
```

#### - Helm
  To install:
  ```bash
$ curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
$ chmod 700 get_helm.sh
$ ./get_helm.sh
  ```
#### - Kind
   ```bash
go install sigs.k8s.io/kind@v0.23.0
   ```

### The Tyk Helm repo
```bash
helm repo add tyk-helm https://helm.tyk.io/public/helm/charts/
helm repo update
```

# How to create a kind cluster:
```bash
make create-kind-cluster
```
* the cluster will be created with the name `kind`, set CLUSTER_NAME to change the name of the cluster.

# How to delete a kind cluster:
```bash
    make delete-kind-cluster
```

# How to get your values.yaml files
```bash
helm show values tyk-helm/tyk-oss > ossValues.yaml
```
```bash
helm show values tyk-helm/tyk-oss > dataPlaneValues.yaml
```

# How to install the required dependencies in the kind cluster
### Create the namespace
```bash
kubectl create namespace tyk
```

### Install the required 

#### - Redis
```bash

```
