var bug_tt7639 = new TykJS.TykMiddleware.NewMiddleware({});
bug_tt7639.NewProcessRequest(function(request, session, spec) {

  log("Running POST PROCESSOR middleware");
  log("I am POST Middleware.")
  
  // commented out, but can be uncommented to trigger a failure 
  // because failure_trigger is not defined
  // log(failure_trigger)

  return bug_tt7639.ReturnData(request, session.meta_data);
});