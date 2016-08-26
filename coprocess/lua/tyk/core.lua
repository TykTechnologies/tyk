print("Loading core")

local cjson = require "cjson"

function dispatch(raw_object)
  object = cjson.decode(raw_object)
  object['request']['set_headers'] = {}
  object['request']['set_headers']["testkey"] = "testvalue"
  new_object = cjson.encode(object)
  return new_object, #new_object
end
