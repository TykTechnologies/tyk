// ---- Sample middleware creation by end-user -----
var sampleMiddleware = new TykJS.TykMiddleware.NewMiddleware({});

sampleMiddleware.NewProcessRequest(function(request, session) {
    // You can log to Tyk console output by calloing the built-in log() function:
    log("Running sample JSVM middleware")
    
    // Set and Delete headers in an outbound request
    request.SetHeaders["User-Agent"] = "Tyk-Custom-JSVM-Middleware";
    //request.DeleteHeaders.push("Authorization");
    
    // Change the outbound URL Path (only fragment, domain is fixed)
    // request.URL = "/get";
    
    // Add or delete request parmeters, these are encoded for the request as needed.
    request.AddParams["test_param"] = "My Teapot";
    request.DeleteParams.push("delete_me");
    
    // Override the body:
    request.Body = "New Request body"
    
    // If you have multiple middlewares that need to communicate, set or read keys in the session object.
    // This will only work in a postprocessing MW
    if (session.meta_data) {
        session.meta_data["MiddlewareDataString"] = "SomeValue";
    }
       
    // You MUST return both the request and session metadata    
    return sampleMiddleware.ReturnData(request, session.meta_data);
});

// Ensure init with a post-declaration log message
log("Sample middleware initialised");