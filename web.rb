require 'sinatra'
require 'base64'
require 'json'

get '/' do
  haml :index, locals: { policy: s3_upload_policy_document,
                         signature: s3_upload_signature}
end

# generate the policy document that amazon is expecting.
def s3_upload_policy_document
  Base64.encode64(
    {
      expiration: (Time.now.utc + 30 * 60).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
      conditions: [
        { bucket: 'uploads.pallit.io' },
        { acl: 'public-read' },
        ["starts-with", "$key", ""]#,
        # { success_action_status: '201' }
      ]
    }.to_json
  ).gsub(/\n|\r/, '')
end

# sign our request by Base64 encoding the policy document.
def s3_upload_signature
  @signature ||= Base64.encode64(
    OpenSSL::HMAC.digest(
      OpenSSL::Digest::Digest.new('sha1'),
      ENV['AWS_SECRET_ACCESS_KEY'],
      s3_upload_policy_document
    )
  ).gsub(/\n/, '')
end