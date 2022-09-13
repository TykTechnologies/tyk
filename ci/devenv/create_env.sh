#!/bin/sh
cd /repo/ci/terraform/environment
terraform init
terraform workspace new ${CLUSTER}
terraform workspace show
echo "CALL - Generate templates on EFS"
echo "CALL - Make input var files"
terraform apply -auto-approve -var-file=master.tfvars