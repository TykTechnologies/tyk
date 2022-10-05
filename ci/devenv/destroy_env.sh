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
terraform workspace select ${CLUSTER}
terraform workspace show
terraform destroy -auto-approve -var "name=${CLUSTER}" -var-file=master.tfvars
terraform workspace select default
terraform workspace delete ${CLUSTER}