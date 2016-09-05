require '../../bindings/ruby/dispatcher'

class SampleServer < Coprocess::Dispatcher::Service
  def dispatch(request, _unused_call)
    print request.inspect
    puts
    return request
  end
end

def main
  s = GRPC::RpcServer.new
  s.add_http2_port('0.0.0.0:5555', :this_port_is_insecure)
  s.handle(SampleServer)
  s.run_till_terminated
end

main
