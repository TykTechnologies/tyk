this_dir = File.expand_path(File.dirname(__FILE__))
lib_dir = File.join(this_dir, 'lib')
$LOAD_PATH.unshift(lib_dir) unless $LOAD_PATH.include?(lib_dir)

require 'grpc'

require File.join(this_dir, 'coprocess_object_pb')
# require File.join(this_dir, 'coprocess_return_overrides_pb' )
# require File.join(this_dir, 'coprocess_mini_request_object_pb')

module Coprocess
  module Dispatcher
    class Service

      include GRPC::GenericService

      self.marshal_class_method = :encode
      self.unmarshal_class_method = :decode
      self.service_name = 'coprocess.Dispatcher'

      rpc :Dispatch, Coprocess::Object, Coprocess::Object
      rpc :DispatchEvent, Coprocess::Event, Coprocess::EventReply
    end

    Stub = Service.rpc_stub_class

    class HookNotImplemented < Exception
    end
  end
end
