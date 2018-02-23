log("====> JS Auth initialising");

var ottoAuthExample = new TykJS.TykMiddleware.NewMiddleware({});

ottoAuthExample.NewProcessRequest(function(request, session) {
    log("----> Running ottoAuthExample JSVM Auth Middleware")

    var thisToken = request.Params["auth"];

    if (thisToken == undefined) {
        // no token at all?
        request.ReturnOverrides.ResponseCode = 401
        request.ReturnOverrides.ResponseError = 'Header missing (JS middleware)'
        return ottoAuthExample.ReturnData(request, {});
    }

    if (thisToken != "foobar") {
        request.ReturnOverrides.ResponseCode = 401
        request.ReturnOverrides.ResponseError = 'Not authorized (JS middleware)'
        return ottoAuthExample.ReturnData(request, {});
    }

    var thisSession = {
        "allowance": 100,
        "rate": 100,
        "per": 1,
        "quota_max": -1,
        "quota_renews": 1406121006,
        "access_rights": {}
    };

    return ottoAuthExample.ReturnAuthData(request, thisSession);
});

// Ensure init with a post-declaration log message
log("====> JS Auth initialised");
