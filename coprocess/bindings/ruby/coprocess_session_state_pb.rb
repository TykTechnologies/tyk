# frozen_string_literal: true
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: coprocess_session_state.proto

require 'google/protobuf'


descriptor_data = "\n\x1d\x63oprocess_session_state.proto\x12\tcoprocess\"*\n\nAccessSpec\x12\x0b\n\x03url\x18\x01 \x01(\t\x12\x0f\n\x07methods\x18\x02 \x03(\t\"s\n\x10\x41\x63\x63\x65ssDefinition\x12\x10\n\x08\x61pi_name\x18\x01 \x01(\t\x12\x0e\n\x06\x61pi_id\x18\x02 \x01(\t\x12\x10\n\x08versions\x18\x03 \x03(\t\x12+\n\x0c\x61llowed_urls\x18\x04 \x03(\x0b\x32\x15.coprocess.AccessSpec\"/\n\rBasicAuthData\x12\x10\n\x08password\x18\x01 \x01(\t\x12\x0c\n\x04hash\x18\x02 \x01(\t\"\x19\n\x07JWTData\x12\x0e\n\x06secret\x18\x01 \x01(\t\"!\n\x07Monitor\x12\x16\n\x0etrigger_limits\x18\x01 \x03(\x01\"\x96\x08\n\x0cSessionState\x12\x12\n\nlast_check\x18\x01 \x01(\x03\x12\x11\n\tallowance\x18\x02 \x01(\x01\x12\x0c\n\x04rate\x18\x03 \x01(\x01\x12\x0b\n\x03per\x18\x04 \x01(\x01\x12\x0f\n\x07\x65xpires\x18\x05 \x01(\x03\x12\x11\n\tquota_max\x18\x06 \x01(\x03\x12\x14\n\x0cquota_renews\x18\x07 \x01(\x03\x12\x17\n\x0fquota_remaining\x18\x08 \x01(\x03\x12\x1a\n\x12quota_renewal_rate\x18\t \x01(\x03\x12@\n\raccess_rights\x18\n \x03(\x0b\x32).coprocess.SessionState.AccessRightsEntry\x12\x0e\n\x06org_id\x18\x0b \x01(\t\x12\x17\n\x0foauth_client_id\x18\x0c \x01(\t\x12:\n\noauth_keys\x18\r \x03(\x0b\x32&.coprocess.SessionState.OauthKeysEntry\x12\x31\n\x0f\x62\x61sic_auth_data\x18\x0e \x01(\x0b\x32\x18.coprocess.BasicAuthData\x12$\n\x08jwt_data\x18\x0f \x01(\x0b\x32\x12.coprocess.JWTData\x12\x14\n\x0chmac_enabled\x18\x10 \x01(\x08\x12\x13\n\x0bhmac_secret\x18\x11 \x01(\t\x12\x13\n\x0bis_inactive\x18\x12 \x01(\x08\x12\x17\n\x0f\x61pply_policy_id\x18\x13 \x01(\t\x12\x14\n\x0c\x64\x61ta_expires\x18\x14 \x01(\x03\x12#\n\x07monitor\x18\x15 \x01(\x0b\x32\x12.coprocess.Monitor\x12!\n\x19\x65nable_detailed_recording\x18\x16 \x01(\x08\x12\x37\n\x08metadata\x18\x17 \x03(\x0b\x32%.coprocess.SessionState.MetadataEntry\x12\x0c\n\x04tags\x18\x18 \x03(\t\x12\r\n\x05\x61lias\x18\x19 \x01(\t\x12\x14\n\x0clast_updated\x18\x1a \x01(\t\x12\x1d\n\x15id_extractor_deadline\x18\x1b \x01(\x03\x12\x18\n\x10session_lifetime\x18\x1c \x01(\x03\x12\x16\n\x0e\x61pply_policies\x18\x1d \x03(\t\x12\x13\n\x0b\x63\x65rtificate\x18\x1e \x01(\t\x12\x17\n\x0fmax_query_depth\x18\x1f \x01(\x03\x1aP\n\x11\x41\x63\x63\x65ssRightsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12*\n\x05value\x18\x02 \x01(\x0b\x32\x1b.coprocess.AccessDefinition:\x02\x38\x01\x1a\x30\n\x0eOauthKeysEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x42\x0cZ\n/coprocessb\x06proto3"

pool = Google::Protobuf::DescriptorPool.generated_pool
pool.add_serialized_file(descriptor_data)

module Coprocess
  AccessSpec = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.AccessSpec").msgclass
  AccessDefinition = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.AccessDefinition").msgclass
  BasicAuthData = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.BasicAuthData").msgclass
  JWTData = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.JWTData").msgclass
  Monitor = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.Monitor").msgclass
  SessionState = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.SessionState").msgclass
end
