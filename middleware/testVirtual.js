function thisTest(request, session, config) {
	// Set up a response object
	var response = {
		Body: ""
		Headers: {
			"test": "virtual-header-1", 
			"test-2": "virtual-header-2",
			"content-type": "application/json"
		},
		Code: 200
	}

	// Batch request
	var batch = {
	    "requests": [
	        {
	            "method": "GET",
	            "headers": {
	                "x-tyk-test": "1",
	                "x-tyk-version": "1.2",
	                "authorization": "1dbc83b9c431649d7698faa9797e2900f"
	            },
	            "body": "",
	            "relative_url": "http://httpbin.org/get"
	        },
	        {
	            "method": "GET",
	            "headers": {},
	            "body": "",
	            "relative_url": "http://httpbin.org/user-agent"
	        }
	    ],
	    "suppress_parallel_execution": false
	}

	log("[Virtual Test] Making Upstream Batch Request")
	var newBody = TykBatchRequest(JSON.stringify(batch))

	// We know that the requests return JSON in their body, lets flatten it
	var asJS = JSON.parse(newBody)
	for (var i in asJS) {
		asJS[i].body = JSON.parse(asJS[i].body)
	}

	// We need to send a string object back to Tyk to embed in the response
	response.Body = JSON.stringify(asJS)

	return TykJsResponse(response, session.meta_data)
	
}
log("Virtual Test initialised")