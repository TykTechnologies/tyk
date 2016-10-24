require '../../bindings/ruby/dispatcher'

require '../../bindings/ruby/coprocess_session_state_pb'

require 'json'

class SampleServer < Coprocess::Dispatcher::Service

  # Implements a dynamic dispatcher for CP objects, this class should provide methods for your hooks (see MyPreMiddleware).
  def dispatch(coprocess_object, _unused_call)
    begin
      if self.respond_to?(coprocess_object.hook_name)
        coprocess_object = self.send(coprocess_object.hook_name, coprocess_object)
      else
        raise Coprocess::Dispatcher::HookNotImplemented
      end
    rescue Coprocess::Dispatcher::HookNotImplemented
      puts "Hook not implemented: #{coprocess_object.hook_name}"
    rescue Exception => e
      puts "Couldn't dispatch: #{e}"
    end

    return coprocess_object
  end

  # Implements an event dispatcher.
  def dispatch_event(event_wrapper, _unused_call)
    event = JSON.parse(event_wrapper.payload)
    puts "dispatch_event: #{event}"
    return Coprocess::EventReply.new
  end

  def MyPreMiddleware(coprocess_object)
    coprocess_object.request.set_headers["rubyheader"] = "rubyvalue"
    return coprocess_object
  end

  def MyAuthCheck(coprocess_object)
    puts "Calling MyAuthCheck"
    valid_token = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    request_token = coprocess_object.request.headers["Authorization"]

    if request_token == nil
      puts "(Using form)"
      request_token = coprocess_object.request.params["key"]
    end

    if request_token.include?(valid_token)
      new_session = Coprocess::SessionState.new
      new_session.rate = 1000
      new_session.per = 10
      new_session.quota_max = 60
      new_session.quota_renews = 1474057703
      new_session.quota_remaining = 0
      new_session.quota_renewal_rate = 120
      new_session.expires = 1474057703

      # Only set this on create!
      new_session.last_updated = (Time.now.to_i + 10).to_s

      # ID Extractor Deadline!
      new_session.id_extractor_deadline = 20

      # new_session.session_lifetime = 99

      coprocess_object.metadata["token"] = "mytoken"
      coprocess_object.session = new_session
    else
      coprocess_object.request.return_overrides.response_code = 401
      coprocess_object.request.return_overrides.response_error = 'Not authorized (gRPC/Ruby middleware)'
    end

    return coprocess_object
  end
end

def main
  s = GRPC::RpcServer.new
  s.add_http2_port('0.0.0.0:5555', :this_port_is_insecure)
  s.handle(SampleServer)
  s.run_till_terminated
end

main
