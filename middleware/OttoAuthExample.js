log("====> JS Auth initialising");

var OttoAuthExample = new TykJS.TykMiddleware.NewMiddleware({});

OttoAuthExample.NewProcessRequest(function(request, session) {
    log("----> Running OttoAuthExample JSVM Auth Middleware")
   
    var thisToken = request.Params["auth"];
   
    if (thisToken == undefined) {
        // no token at all?
        request.ReturnOverrides.ResponseCode = 401
        request.ReturnOverrides.ResponseError = 'Header missing (JS middleware)'
        return OttoAuthExample.ReturnData(request, {});
    }
 
    if (thisToken != "foobar") {
        request.ReturnOverrides.ResponseCode = 401
        request.ReturnOverrides.ResponseError = 'Not authorized (JS middleware)'
        return OttoAuthExample.ReturnData(request, {});
    } 

    var thisSession = {    
        "allowance": 100,
        "rate": 100,
        "per": 1,
        "quota_max": -1,
        "quota_renews": 1406121006,
        "access_rights": {}
    };
    
    return OttoAuthExample.ReturnAuthData(request, thisSession);
});
 
// Ensure init with a post-declaration log message
log("====> JS Auth initialised");