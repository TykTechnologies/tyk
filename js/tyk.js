// ----- Tyk Middleware JS definition: this should be in the global context -----

var TykJS = {
        TykMiddleware: {
            MiddlewareComponentMeta: function(configuration) {
                this.configuration = configuration;
            }
        },
        TykEventHandlers: {
                EventHandlerComponentMeta: function() {}
        }
};

TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.ProcessRequest = function(request, session) {
    log("Process Request Not Implemented");
    return request;
};

TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.DoProcessRequest = function(request, session) {
    var processed_request = this.ProcessRequest(request, session);

    if (!processed_request) {
        log("Middleware didn't return request object!");
        return;
    }
    
    // Reset the headers object
    processed_request.Request.Headers = {}

    return JSON.stringify(processed_request)
};

// The user-level middleware component
TykJS.TykMiddleware.NewMiddleware = function(configuration) {
    TykJS.TykMiddleware.MiddlewareComponentMeta.call(this, configuration);
};

// Set up object inheritance
TykJS.TykMiddleware.NewMiddleware.prototype = Object.create(TykJS.TykMiddleware.MiddlewareComponentMeta.prototype);
TykJS.TykMiddleware.NewMiddleware.prototype.constructor = TykJS.TykMiddleware.NewMiddleware;

TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessRequest = function(callback) {
    this.ProcessRequest = callback;
};

TykJS.TykMiddleware.NewMiddleware.prototype.ReturnData = function(request, session) {
    return {Request: request, SessionMeta: session}
};

TykJS.TykMiddleware.NewMiddleware.prototype.ReturnAuthData = function(request, session) {
    return {Request: request, Session: session}
};

// ---- End middleware implementation for global context ----

// -- Start Event Handler implementation ----

TykJS.TykEventHandlers.EventHandlerComponentMeta.prototype.DoProcessEvent = function(event, context) {
    // call the handler
    log("Calling built - in handle")
    this.Handle(event, context);
    return
};

TykJS.TykEventHandlers.EventHandlerComponentMeta.prototype.Handle = function(request, context) {
    log("Handler not implemented!");
    return request;
};

// The user-level event handler component
TykJS.TykEventHandlers.NewEventHandler = function() {
    TykJS.TykEventHandlers.EventHandlerComponentMeta.call(this);
};

// Set up object inheritance for events
TykJS.TykEventHandlers.NewEventHandler.prototype = Object.create(TykJS.TykEventHandlers.EventHandlerComponentMeta.prototype);
TykJS.TykEventHandlers.NewEventHandler.prototype.constructor = TykJS.TykEventHandlers.NewEventHandler;

TykJS.TykEventHandlers.NewEventHandler.prototype.NewHandler = function(callback) {
    this.Handle = callback;
};
