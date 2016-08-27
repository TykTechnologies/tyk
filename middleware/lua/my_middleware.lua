  function MyPreMiddleware(request, session, spec)
  print("MyPreMiddleware, request=", request, "session=", session, "spec=", spec)
  tyk.req.set_header("myluaheader", "myluavalue")
  -- print("User-Agent header:", tyk.header["User-Agent"])
  return request, session
end
