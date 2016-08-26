local request = {}

function request.set_header(key, value)
  if object['request']['set_headers'] == nil then
    object['request']['set_headers'] = {}
  end
  object['request']['set_headers'][key] = value
end

return request
