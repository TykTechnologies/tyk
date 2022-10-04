#!/bin/sh
set -ea
cd /repo/ci/terraform/environment

if [[ -z "${CLUSTER}" ]];then
	echo "Error: Cluster name not defined"
	exit 1
fi
echo "DEBUG: CLUSTER = ${CLUSTER}"
ls
terraform workspace select ${CLUSTER}
terraform init
terraform workspace show
terraform destroy -auto-approve -var "name=${CLUSTER}" -var-file=master.tfvars