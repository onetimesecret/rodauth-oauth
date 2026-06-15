# frozen_string_literal: true

require "test_helper"
require "rack/urlmap"

# Exercises +oauth_mount_prefix+ with the authorization server actually mounted
# under a Rack SCRIPT_NAME (via Rack::URLMap), which is the scenario the setting
# exists for: the mount point is stripped from PATH_INFO, so route *matching*
# still works off +remaining_path+ ("/token"), but +request.path+ is the
# browser-absolute "/auth/token". Without the setting the gem's per-feature
# +check_csrf?+ exemptions (which compare against +token_path+ etc.) miss.
class RodauthOAuthMountPrefixTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_csrf_exempt_with_mount_prefix_under_script_name
    rodauth do
      oauth_mount_prefix "/auth"
    end
    setup_application
    mount_under_script_name!

    oauth_app = oauth_application
    grant = set_oauth_grant(oauth_application: oauth_app)
    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    # Form-encoded POST with no CSRF token. /token is exempt, so this must be
    # processed (not blocked) even though request.path is "/auth/token".
    post("/auth/token", grant_type: "authorization_code",
                        code: grant[:code],
                        redirect_uri: grant[:redirect_uri])

    verify_response(200)
    verify_token_common_response(json_body)
  end

  def test_token_csrf_enforced_without_mount_prefix_under_script_name
    setup_application
    mount_under_script_name!

    oauth_app = oauth_application
    grant = set_oauth_grant(oauth_application: oauth_app)
    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    # Same request, but without oauth_mount_prefix the exemption misses and the
    # tokenless form POST is rejected by CSRF (route_csrf raises, or a non-2xx).
    # Tolerant of either manifestation so the guard survives CSRF-handling churn.
    csrf_enforced =
      begin
        post("/auth/token", grant_type: "authorization_code",
                            code: grant[:code],
                            redirect_uri: grant[:redirect_uri])
        last_response.status != 200
      rescue Roda::RodaPlugins::RouteCsrf::InvalidToken
        true
      end

    assert csrf_enforced,
           "expected CSRF to be (incorrectly) enforced on /auth/token without oauth_mount_prefix"
  end

  def test_discovery_metadata_under_script_name_mount
    rodauth do
      oauth_mount_prefix "/auth"
    end
    setup_application(&:load_oauth_server_metadata_route)
    mount_under_script_name!

    get("/auth/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org/auth"
    assert json_body["authorization_endpoint"] == "http://example.org/auth/authorize"
    assert json_body["token_endpoint"] == "http://example.org/auth/token"
  end

  private

  # Re-wrap the application built by the harness so it is served under the
  # "/auth" SCRIPT_NAME, mirroring how a host app mounts it with Rack::URLMap.
  def mount_under_script_name!
    self.app = Rack::URLMap.new("/auth" => app)
  end
end
