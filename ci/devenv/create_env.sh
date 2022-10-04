#!/bin/sh
cd /repo/ci/terraform/environment
#cd ../terraform/environment
ls
terraform init
terraform workspace select kikitest3
terraform workspace show
# echo "CALL - Generate templates on EFS"
# echo "CALL - Make input var files"
terraform apply -auto-approve -var-file=master.tfvars