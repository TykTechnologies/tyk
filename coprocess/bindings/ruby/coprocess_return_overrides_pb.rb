require 'google/protobuf'

Google::Protobuf::DescriptorPool.generated_pool.build do
  add_message "coprocess.ReturnOverrides" do
    optional :response_code, :int32, 1
    optional :response_error, :string, 2
  end
end

module Coprocess
  ReturnOverrides = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.ReturnOverrides").msgclass
end
