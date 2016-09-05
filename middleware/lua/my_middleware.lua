  function MyPreMiddleware(request, session, spec)
  print("MyPreMiddleware, request=", request, "session=", session, "spec=", spec)
  tyk.req.set_header("myluaheader", "myluavalue")
  local headers = tyk.req.get_headers()
  print(headers)
  tyk.req.clear_header("User-Agent")
  -- print("User-Agent header:", tyk.header["User-Agent"])
  return request, session
end
