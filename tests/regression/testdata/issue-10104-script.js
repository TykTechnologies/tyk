var bug_10104 = new TykJS.TykMiddleware.NewMiddleware({});

bug_10104.NewProcessRequest(function (request, session, spec) {
    var metaData = {};
    log('just some logging') 
    return bug_10104.ReturnData(request, metaData);
});
