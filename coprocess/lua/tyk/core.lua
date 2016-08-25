print("Loading core")

local cjson = require "cjson"

function dispatch(raw_object)
  object = cjson.decode(raw_object)
  -- print(object['request'])
  object['request']['set_headers'] = {}
  object['request']['set_headers']["testkey"] = "testvalue"
  object['request']['return_overrides']['response_code'] = 500
  new_object = cjson.encode(object)
  -- print("new_object =", new_object)
  return new_object, #new_object
end
