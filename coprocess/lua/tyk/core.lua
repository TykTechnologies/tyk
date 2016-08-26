print("Loading core")

local cjson = require "cjson"

function dispatch(raw_object)
  object = cjson.decode(raw_object)

  -- Environment reference to hook.
  hook_name = object['hook_name']
  hook_f = _G[hook_name]
  is_custom_key_auth = false

  -- Set a flag if this is a custom key auth hook.
  if object['hook_type'] == 4 then
    is_custom_key_auth = true
  end

  -- Call the hook and return a serialized version of the modified object.
  if hook_f then
    local request, session, spec, metadata

    if custom_key_auth then
      request, session, metadata, spec = hook_f(object['request'], object['session'], object['metadata'], object['spec'])
    else
      request, session, spec = hook_f(object['request'], object['session'], object['spec'])
    end

    -- Modify the CP object.
    object['request'] = request
    object['session'] = session
    object['spec'] = spec
    object['metadata'] = metadata

    raw_new_object = cjson.encode(object)

    return raw_new_object, #raw_new_object

  -- Return the original object and print an error.
  else
    print("Lua: hook doesn't exist!")
    return raw_object, #raw_object
  end

end
