function MyPostMiddleware(request, session, spec)
  print("MyPostMiddleware, request=", request, "session=", session, "spec=", spec)
  tyk.req.set_header("myluaheader", "myluavalue")
  print("User-Agent header:", tyk.header["User-Agent"])
  return request, session
end

function MyAuthCheck(request, session, metadata, spec)
  print("MyPostMiddleware, request=", request, "session=", session, "metadata=", metadata, "spec=", spec)
  return request, session, metadata
end
