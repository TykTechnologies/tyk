// ---- Sample middleware creation by end-user -----
var sampleHandler = new TykJS.TykEventHandlers.NewEventHandler({});

sampleHandler.NewHandler(function(event, context) {
    // You can log to Tyk console output by calloing the built-in log() function:
    log("Running sample JSVM Handler")
    
    /* The Event object:
    {
        "EventType": "Event Typ Code",
        "EventMetaData": {
            "Message": "MEvent descirption",
            "Path": "/{{api_id}}/{{path}}",
            "Origin": "1.1.1.1:PORT",
            "Key": "{{Auth Key}}",
            "OriginatingRequest": "" // B64 Encoded Request in wire protocol
        },
        "TimeStamp": "2015-01-15 17:21:15.111157073 +0000 UTC"
    }
    
    */
    
    return
});

// Ensure init with a post-declaration log message
log("Sample JS event handler initialised");