local cjson = require "cjson"

-- Make the current object accessible for helpers.
object = nil

-- The bundle will declare "request":

tyk = {
  req = request,
  header=nil
}

function dispatch(raw_object)
  object = cjson.decode(raw_object)
  raw_new_object = nil

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
    local new_request, new_session, metadata

    -- tyk.header = object['request']['headers']

    if custom_key_auth then
      new_request, new_session, metadata = hook_f(object['request'], object['session'], object['metadata'], object['spec'])
    else
      new_request, new_session = hook_f(object['request'], object['session'], object['spec'])
    end

    -- Modify the CP object.
    object['request'] = new_request
    object['session'] = new_session
    object['metadata'] = metadata

    raw_new_object = cjson.encode(object)

    -- return raw_new_object, #raw_new_object

  -- Return the original object and print an error.
  else
    return raw_object, #raw_object
  end

  return raw_new_object, #raw_new_object
end

function dispatch_event(raw_event)
  print("dispatch_event:", raw_event)
end
