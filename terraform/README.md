##Deploying Tyk with Terraform

Create a `terraform.tfvars` file with the following contents, but customising for your requirements.

```
do_token="SOME_TOKEN"
ssh_fingerprint="98:98:4b:4d:0a:4d:20:d9:8a:18:9f:3d:12:af:ab:e5"
key_path = "~/.ssh/id_rsa"
region="lon1"
num_instances=1
size="s-1vcpu-1gb"
tag="tyk"
```

Modify `main.tf` according to your requirements.

`terraform init` to ensure all required modules are downloaded.
`terraform plan`
`terraform apply`

---

TODO

* Support AWS, Azure & GCP Providers
* MongoDB Module
* Tyk Pump Module
* Tyk Dashboard
