#!/bin/bash

NAMESPACE=$1  # get namespace from command line argument

helm install tyk-mongo bitnami/mongodb --set "replicaSet.enabled=true" -n ${NAMESPACE} --version 15.1.3 --set "extraEnvVars[0].name=EXPERIMENTAL_DOCKER_DESKTOP_FORCE_QEMU" --set "extraEnvVars[0].value=\"1\""

MONGODB_ROOT_PASSWORD=$(kubectl get secret --namespace tyk tyk-mongo-mongodb -o jsonpath="{.data.mongodb-root-password}" | base64 -d)

# Uncomment the mongoURL line if it's commented out
if [ "$(uname -s)" = "Darwin" ]; then
  sed -i "" "s/# mongoURL: mongodb:\/\/root:pass@tyk-mongo-mongodb.tyk.svc:27017\/tyk_analytics?authSource=admin/mongoURL: mongodb:\/\/root:pass@tyk-mongo-mongodb.tyk.svc:27017\/tyk_analytics?authSource=admin/g" k8s/controlPlaneValues.yaml
else
  sed -i "s/# mongoURL: mongodb:\/\/root:pass@tyk-mongo-mongodb.tyk.svc:27017\/tyk_analytics?authSource=admin/mongoURL: mongodb:\/\/root:pass@tyk-mongo-mongodb.tyk.svc:27017\/tyk_analytics?authSource=admin/g" k8s/controlPlaneValues.yaml
fi

# Replace the existing password with the new one
if [ "$(uname -s)" = "Darwin" ]; then
  sed -i "" "s/mongodb:\/\/root:[^@]*@/mongodb:\/\/root:${MONGODB_ROOT_PASSWORD}@/g" k8s/controlPlaneValues.yaml
else
  sed -i "s/mongodb:\/\/root:[^@]*@/mongodb:\/\/root:${MONGODB_ROOT_PASSWORD}@/g" k8s/controlPlaneValues.yaml
fi