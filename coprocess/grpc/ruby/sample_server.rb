require '../../bindings/ruby/dispatcher'

class SampleServer < Coprocess::Dispatcher::Service

  def MyPreMiddleware(coprocess_object)
    coprocess_object.request.set_headers["rubyheader"] = "rubyvalue"
    return coprocess_object
  end

  # Implements a dynamic dispatcher, this class should implement your hooks.
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
end

def main
  s = GRPC::RpcServer.new
  s.add_http2_port('0.0.0.0:5555', :this_port_is_insecure)
  s.handle(SampleServer)
  s.run_till_terminated
end

main
