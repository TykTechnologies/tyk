[
    {
	%{if port != null }
        "portMappings": [
            {
                "containerPort": ${port}
            }
        ],
	%{ endif }
        "mountPoints": ${jsonencode([ for m in mounts: { "sourceVolume": m.src, "containerPath": m.dest, "readOnly": true }])},
        "environment": ${jsonencode([ for e in env: { "name": e.name, "value": e.value }])},
        "secrets": ${jsonencode([ for s in secrets: { "name": s.name, "valueFrom": s.from }])},
        "image": "${image}",
        "name": "${name}",
        "command": ${jsonencode(command)},
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": "${log_group}",
                "awslogs-stream-prefix": "${name}",
                "awslogs-region": "${region}"
            }
        }
    }

]
