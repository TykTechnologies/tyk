// ---- Sample session managing middleware -----
var sessionHandler = new TykJS.TykEventHandlers.NewEventHandler({});

sessionHandler.NewHandler(function(event, context) {
    // You can log to Tyk console output by calloing the built-in log() function:
    log("Running Session JSVM Handler");
    
    // Use the TykGetKeyData function to retrieve a session from the session store
    var thisSession = JSON.parse(TykGetKeyData(event.EventMetaData.Key, context.APIID))
    log("Expires: " + thisSession.expires)
    
    // You can modify the object just like with the REST API
    thisSession.expires = thisSession.expires + 1000;
    
    // Use TykSetKeyData to set the key data back in the session store
    TykSetKeyData(event.EventMetaData.Key, JSON.stringify(thisSession));
    
});

// Ensure init with a post-declaration log message
log("Session JS event handler initialised");