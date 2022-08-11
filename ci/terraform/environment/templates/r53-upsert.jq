{
    "Comment": "Automated update",
    "Changes": [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": env.fqdn,
                "Type": "A",
                "SetIdentifier": "0",
                "Region": env.region,
                "TTL": 10,
                "ResourceRecords": [
                    {
                        "Value": env.public_ip
                    }
                ]
            }
        }
    ]
}
