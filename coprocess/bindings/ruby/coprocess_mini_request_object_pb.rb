# frozen_string_literal: true
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: coprocess_mini_request_object.proto

require 'google/protobuf'

require 'coprocess_return_overrides_pb'


descriptor_data = "\n#coprocess_mini_request_object.proto\x12\tcoprocess\x1a coprocess_return_overrides.proto\"\x9a\x06\n\x11MiniRequestObject\x12:\n\x07headers\x18\x01 \x03(\x0b\x32).coprocess.MiniRequestObject.HeadersEntry\x12\x41\n\x0bset_headers\x18\x02 \x03(\x0b\x32,.coprocess.MiniRequestObject.SetHeadersEntry\x12\x16\n\x0e\x64\x65lete_headers\x18\x03 \x03(\t\x12\x0c\n\x04\x62ody\x18\x04 \x01(\t\x12\x0b\n\x03url\x18\x05 \x01(\t\x12\x38\n\x06params\x18\x06 \x03(\x0b\x32(.coprocess.MiniRequestObject.ParamsEntry\x12?\n\nadd_params\x18\x07 \x03(\x0b\x32+.coprocess.MiniRequestObject.AddParamsEntry\x12I\n\x0f\x65xtended_params\x18\x08 \x03(\x0b\x32\x30.coprocess.MiniRequestObject.ExtendedParamsEntry\x12\x15\n\rdelete_params\x18\t \x03(\t\x12\x34\n\x10return_overrides\x18\n \x01(\x0b\x32\x1a.coprocess.ReturnOverrides\x12\x0e\n\x06method\x18\x0b \x01(\t\x12\x13\n\x0brequest_uri\x18\x0c \x01(\t\x12\x0e\n\x06scheme\x18\r \x01(\t\x12\x10\n\x08raw_body\x18\x0e \x01(\x0c\x1a.\n\x0cHeadersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x31\n\x0fSetHeadersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a-\n\x0bParamsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x30\n\x0e\x41\x64\x64ParamsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x35\n\x13\x45xtendedParamsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x42\x0cZ\n/coprocessb\x06proto3"

pool = Google::Protobuf::DescriptorPool.generated_pool
pool.add_serialized_file(descriptor_data)

module Coprocess
  MiniRequestObject = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.MiniRequestObject").msgclass
end
