function MyPostMiddleware(request, session, spec)
  print("MyPostMiddleware, request=", request, "session=", session, "spec=", spec)
  return request, session, spec
end

function MyAuthCheck(request, session, metadata, spec)
  print("MyPostMiddleware, request=", request, "session=", session, "metadata=", metadata, "spec=", spec)
  return request, session, metadata, spec
end
