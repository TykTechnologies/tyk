generate:
	rm -f swagger.yml && go run main.go &&  redocly lint  swagger.yml #--generate-ignore-file


diff:
	 oasdiff diff master_swagger.yml swagger.yml  --format=html --exclude-elements=examples,description,summary,extensions,title > diff_result.html
