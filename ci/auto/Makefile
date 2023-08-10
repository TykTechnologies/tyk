REGISTRY := 754489498669.dkr.ecr.eu-central-1.amazonaws.com

login:
	aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin 754489498669.dkr.ecr.eu-central-1.amazonaws.com

master.env:
	docker compose -f tyk.yml -f deps.yml -p $(@:.env=) --env-file $@ up -d

up:
	docker compose -f pro.yml -f deps.yml --env-file master.env --env-file tat.env -p test-proj up -d

down:
	docker compose -f pro.yml -f deps.yml --env-file master.env --env-file tat.env -p test-proj down

.PHONY: master.env
