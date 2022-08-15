#!/bin/zsh

print This script reads the list of envs to DELETE PERMANENTLY from stdin
while read l
do
    terraform workspace select $l
    terraform destroy -var-file=master.tfvars -var "name=$l" -auto-approve
    terraform workspace select default
    terraform workspace delete $l
done
