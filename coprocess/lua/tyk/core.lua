print("Loading core")

function dispatch(buf)
  print("lua_dispatch!")
  return buf, #buf
end
