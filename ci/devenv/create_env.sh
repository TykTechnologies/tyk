#!/bin/sh
set -ea
cd /repo/ci/terraform/environment

if [[ -z "${CLUSTER}" ]];then
	echo "Error: Cluster name not defined"
	exit 1
fi
echo "DEBUG: CLUSTER = ${CLUSTER}"
ls -a
terraform init
terraform workspace new ${CLUSTER}
terraform workspace show
echo "CALL - Generate templates on EFS"
echo "CALL - Make input var files"
terraform apply -auto-approve -var "name=${CLUSTER}" -var-file=master.tfvars