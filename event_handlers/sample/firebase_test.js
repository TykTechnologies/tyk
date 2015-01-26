// ---- Sample firebase middleware -----
var fbHandler = new TykJS.TykEventHandlers.NewEventHandler({});

fbHandler.NewHandler(function(event, context) {
    // You can log to Tyk console output by calloing the built-in log() function:
    log("Running firebase JSVM Handler");
    
    /*      The Event object:
            {
                "EventType": "Event Typ Code",
                "EventMetaData": {
                    "Message": "MEvent descirption",
                    "Path": "/{{api_id}}/{{path}}",
                    "Origin": "1.1.1.1:PORT",
                    "Key": "{{Auth Key}}"
                },
                "TimeStamp": "2015-01-15 17:21:15.111157073 +0000 UTC"
            }
    */
    
    newRequest = {
        "Method": "POST",
        "Body": JSON.stringify(event),
        "Headers": {},
        "Domain": "",
        "Resource": "/middleware/fb.json",
        "FormData": {}
    };
    
    if (newRequest.Domain === "") {
        log("Please specify a Firebase endpoint in the request...");
        return
    }
    
    log("--- CREATING FIREBASE RECORD ---")
    // Use the built-in TykMakeHttpRequest method to make RESTFULL API Calls
    response = TykMakeHttpRequest(JSON.stringify(newRequest)); 
    
    /*      Repsonses are JSON-encoded, so they need to be parsed before using, it looks like this:
    
            type TykJSHttpResponse struct {
                Code int
                Body string
                Headers map[string][]string
            }
    
    */
    
    usableResponse = JSON.parse(response);
    log("Response code: " + usableResponse.Code);
    log("Response body: " + usableResponse.Body);
    log("--- FIREBASE RECORD CREATED ---")
    
    fbResponse = JSON.parse(usableResponse.Body);
    getDetails = {
        "Method": "GET",
        "Body": "",
        "Headers": {},
        "Domain": "https://glaring-torch-9311.firebaseio.com",
        "Resource": "/middleware/fb/" + fbResponse.name + ".json",
        "FormData": {}
    };
    
    log("--- GETTING RECORD FOR VERIFICATION ---")
    log("URL: /middleware/fb/" + fbResponse.name + ".json")
    responseDetails = JSON.parse(TykMakeHttpRequest(JSON.stringify(getDetails))); 
    objDetails = JSON.parse(responseDetails.Body)
    log("Key: " + objDetails.EventMetaData.Key);
    log("Message: " + objDetails.EventMetaData.Message);
    log("--- DONE ---")
});

// Ensure init with a post-declaration log message
log("Firebase JS event handler initialised");