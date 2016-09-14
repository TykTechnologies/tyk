require 'google/protobuf'

Google::Protobuf::DescriptorPool.generated_pool.build do
  add_message "coprocess.AccessSpec" do
    optional :url, :string, 1
    repeated :methods, :string, 2
  end
  add_message "coprocess.AccessDefinition" do
    optional :api_name, :string, 1
    optional :api_id, :string, 2
    repeated :versions, :string, 3
    repeated :allowed_urls, :message, 4, "coprocess.AccessSpec"
  end
  add_message "coprocess.BasicAuthData" do
    optional :password, :string, 1
    optional :hash, :string, 2
  end
  add_message "coprocess.JWTData" do
    optional :secret, :string, 1
  end
  add_message "coprocess.Monitor" do
    repeated :trigger_limits, :double, 1
  end
  add_message "coprocess.SessionState" do
    optional :last_check, :int64, 1
    optional :allowance, :double, 2
    optional :rate, :double, 3
    optional :per, :double, 4
    optional :expires, :int64, 5
    optional :quota_max, :int64, 6
    optional :quota_renews, :int64, 7
    optional :quota_remaining, :int64, 8
    optional :quota_renewal_rate, :int64, 9
    map :access_rights, :string, :message, 10, "coprocess.AccessDefinition"
    optional :org_id, :string, 11
    optional :oauth_client_id, :string, 12
    map :oauth_keys, :string, :string, 13
    optional :basic_auth_data, :message, 14, "coprocess.BasicAuthData"
    optional :jwt_data, :message, 15, "coprocess.JWTData"
    optional :hmac_enabled, :bool, 16
    optional :hmac_secret, :string, 17
    optional :is_inactive, :bool, 18
    optional :apply_policy_id, :string, 19
    optional :data_expires, :int64, 20
    optional :monitor, :message, 21, "coprocess.Monitor"
    optional :enable_detailed_recording, :bool, 22
    optional :metadata, :string, 23
    repeated :tags, :string, 24
    optional :alias, :string, 25
    optional :last_updated, :string, 26
    optional :id_extractor_deadline, :int64, 27
    optional :session_lifetime, :int64, 28
  end
end

module Coprocess
  AccessSpec = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.AccessSpec").msgclass
  AccessDefinition = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.AccessDefinition").msgclass
  BasicAuthData = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.BasicAuthData").msgclass
  JWTData = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.JWTData").msgclass
  Monitor = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.Monitor").msgclass
  SessionState = Google::Protobuf::DescriptorPool.generated_pool.lookup("coprocess.SessionState").msgclass
end
