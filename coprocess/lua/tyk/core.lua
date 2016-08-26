print("Loading core")

local cjson = require "cjson"

function dispatch(raw_object)
  object = cjson.decode(raw_object)

  -- Environment reference to hook.
  hook_name = object['hook_name']
  hook_f = _G[hook_name]

  -- Call the hook and return a serialized version of the modified object.
  if hook_f then
    new_object = hook_f(object)
    raw_new_object = cjson.encode(new_object)
    return raw_new_object, #raw_new_object

  -- Return the original object and print an error.
  else
    print("Lua: hook doesn't exist!")
    return raw_object, #raw_object
  end

end
