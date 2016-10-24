this_dir = File.expand_path(File.dirname(__FILE__))
lib_dir = File.join(this_dir, 'lib')
$LOAD_PATH.unshift(lib_dir) unless $LOAD_PATH.include?(lib_dir)


require 'google/protobuf'

require File.join(this_dir, 'coprocess_return_overrides_pb' )

Google::Protobuf::DescriptorPool.generated_pool.build do
  add_message "coprocess.MiniRequestObject" do
    map :headers, :string, :string, 1
    map :set_headers, :string, :string, 2
    repeated :delete_headers, :string, 3
    optional :body, :string, 4
    optional :url, :string, 5
    map :params, :string, :string, 6
    map :add_params, :string, :string, 7
    map :extended_params, :string, :string, 8
    repeated :delete_params, :string, 9
    optional :return_overrides, :message, 10, "coprocess.ReturnOverrides"
  end
end

module Coprocess
  MiniRequestObject = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.MiniRequestObject").msgclass
end
