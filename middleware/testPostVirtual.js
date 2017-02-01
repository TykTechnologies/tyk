function thisPostTest(request, session, config) {
	// Set up a response object
	var response = {
		Body: "",
		Headers: {
			"test": "virtual-header-1", 
			"test-2": "virtual-header-2",
			"content-type": "application/json"
		},
		Code: 200
	}

	data_as_json = JSON.parse(request.Body)

	var bod = {
		inbound_array_length: data_as_json.length
	}

	// We need to send a string object back to Tyk to embed in the response
	response.Body = JSON.stringify(bod)

	return TykJsResponse(response, session.meta_data)
	
}
log("Virtual Post test initialised")