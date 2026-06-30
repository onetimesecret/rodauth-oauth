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

  # No-op contract: with oauth_mount_prefix left at its "" default, discovery must
  # behave exactly like upstream — issuer is base_url and endpoint URLs carry no
  # mount point. Guards root-mounted / prefix-only deployments against regressions.
  def test_discovery_metadata_is_unchanged_without_mount_prefix
    setup_application(&:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org"
    assert json_body["token_endpoint"] == "http://example.org/token"
  end

  # /revoke is the load-bearing case from the issue's do-not-regress note. The
  # acceptance criteria require /revoke to skip CSRF for the programmatic (JSON,
  # client-authenticated) call under the mount. With oauth_mount_prefix the
  # oauth_token_revocation check_csrf? (case request.path when revoke_path) lines
  # up with the browser-absolute "/auth/revoke", so a JSON revoke is processed.
  def test_revoke_json_csrf_exempt_with_mount_prefix_under_script_name
    rodauth do
      oauth_mount_prefix "/auth"
    end
    setup_application(:oauth_token_revocation)
    mount_under_script_name!

    oauth_app = oauth_application
    grant = set_oauth_grant_with_token(oauth_application: oauth_app)
    header "Accept", "application/json"
    header "Content-Type", "application/json"
    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post("/auth/revoke", {},
         input: { token_type_hint: "access_token", token: grant[:token] }.to_json)

    assert last_response.status == 200
    assert db[:oauth_grants].where(revoked_at: nil).none?,
           "expected JSON /auth/revoke to be processed (CSRF-exempt) and revoke the token"
  end

  # Boundary / do-not-regress: even WITH the prefix fix, the gem deliberately keeps
  # CSRF *enforced* on form-encoded /revoke (oauth_token_revocation returns
  # !json_request? on the revoke_path match). The mount fix only makes the path
  # comparison hit; it does not — and must not — exempt form revoke. The RFC 7009
  # form-encoded exemption stays a host-app (OTS) concern, not "the gem handles it".
  def test_revoke_form_post_still_csrf_enforced_with_mount_prefix
    rodauth do
      oauth_mount_prefix "/auth"
    end
    setup_application(:oauth_token_revocation)
    mount_under_script_name!

    oauth_app = oauth_application
    grant = set_oauth_grant_with_token(oauth_application: oauth_app)
    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    csrf_enforced =
      begin
        post("/auth/revoke", token_type_hint: "access_token", token: grant[:token])
        last_response.status != 200
      rescue Roda::RodaPlugins::RouteCsrf::InvalidToken
        true
      end

    assert csrf_enforced,
           "expected the gem to still enforce CSRF on form-encoded /auth/revoke"
    assert db[:oauth_grants].where(revoked_at: nil).any?,
           "form revoke must not have gone through"
  end

  # The management features (oauth_application_management / oauth_grant_management)
  # register their routes via request.on(<route>) rather than auth_server_route, and
  # hand-roll their *_path helpers from route_path. Those helpers feed browser-facing
  # form actions, csrf_tag targets, links, and the post-revoke redirect, so under a
  # SCRIPT_NAME mount they must still honor oauth_mount_prefix. Assert the helper
  # outputs directly (no auth/login needed) via a debug route.
  def test_management_path_helpers_honor_mount_prefix_under_script_name
    rodauth do
      oauth_mount_prefix "/auth"
    end
    setup_application(:oauth_application_management, :oauth_grant_management) do |rodauth|
      rodauth.load_oauth_application_management_routes
      rodauth.load_oauth_grant_management_routes
      rodauth.request.is("debug-paths") do
        body = [
          rodauth.oauth_applications_path,
          rodauth.oauth_application_path(42),
          rodauth.oauth_grants_path,
          rodauth.oauth_grant_path(7)
        ].join("|")
        rodauth.request.halt([200, { "content-type" => "text/plain" }, [body]])
      end
    end
    mount_under_script_name!

    get("/auth/debug-paths")

    assert last_response.status == 200
    apps_path, app_path, grants_path, grant_path = last_response.body.split("|")
    assert_equal "/auth/oauth-applications", apps_path
    assert_equal "/auth/oauth-applications/42", app_path
    assert_equal "/auth/oauth-grants", grants_path
    assert_equal "/auth/oauth-grants/7", grant_path
  end

  # The CSRF acceptance criteria name /token, /userinfo, /revoke, /jwks (and the
  # other programmatic endpoints). Each per-feature check_csrf? compares the
  # browser-absolute request.path against the route's *_path, so the exemptions
  # line up only if EVERY auth_server_route endpoint's *_path carries the mount
  # prefix. Rather than seed a bespoke HTTP+auth flow per endpoint, assert the
  # contract generically: under the mount, every endpoint *_path equals its
  # "/auth/<segment>" browser-absolute form (which is exactly what request.path is
  # for a request to that endpoint). The /token and /revoke end-to-end CSRF flows
  # above then exercise the two distinct check_csrf? styles (unconditional vs
  # !json_request?) on top of this.
  def test_all_endpoint_paths_carry_mount_prefix_under_script_name
    rodauth do
      oauth_mount_prefix "/auth"
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
      oauth_application_scopes %w[openid email read write]
    end
    setup_application(
      :oauth_token_revocation, :oauth_token_introspection,
      :oauth_dynamic_client_registration, :oauth_pushed_authorization_request,
      :oauth_device_code_grant, :oidc
    ) do |rodauth|
      rodauth.request.is("debug-paths") do
        names = %i[
          token authorize userinfo revoke introspect jwks
          register par device_authorization device
        ]
        paths = names.each_with_object({}) { |name, h| h[name] = rodauth.public_send(:"#{name}_path") }
        rodauth.request.halt([200, { "content-type" => "application/json" }, [paths.to_json]])
      end
    end
    mount_under_script_name!

    get("/auth/debug-paths")

    assert last_response.status == 200
    paths = json_body
    assert_equal "/auth/token", paths["token"]
    assert_equal "/auth/authorize", paths["authorize"]
    assert_equal "/auth/userinfo", paths["userinfo"]
    assert_equal "/auth/revoke", paths["revoke"]
    assert_equal "/auth/introspect", paths["introspect"]
    assert_equal "/auth/jwks", paths["jwks"]
    assert_equal "/auth/register", paths["register"]
    assert_equal "/auth/par", paths["par"]
    assert_equal "/auth/device-authorization", paths["device_authorization"]
    assert_equal "/auth/device", paths["device"]
  end

  # The recommended ergonomic form derives the prefix from the request:
  # oauth_mount_prefix { request.script_name }. Under the mount, request.script_name
  # is "/auth", so discovery URLs and the issuer are prefixed without hardcoding.
  def test_dynamic_script_name_form_prefixes_under_mount
    rodauth do
      oauth_mount_prefix { request.script_name }
    end
    setup_application(&:load_oauth_server_metadata_route)
    mount_under_script_name!

    get("/auth/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org/auth"
    assert json_body["token_endpoint"] == "http://example.org/auth/token"
  end

  # ...and the same dynamic form must collapse to a no-op when there is no mount:
  # request.script_name is "" at the root, which is also exactly the SCRIPT_NAME the
  # internal_request feature synthesizes. So the dynamic form is safe for both
  # root-mounted deployments and internal requests (no doubling, no raise).
  def test_dynamic_script_name_form_collapses_without_mount
    rodauth do
      oauth_mount_prefix { request.script_name }
    end
    setup_application(&:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org"
    assert json_body["token_endpoint"] == "http://example.org/token"
  end

  private

  # Re-wrap the application built by the harness so it is served under the
  # "/auth" SCRIPT_NAME, mirroring how a host app mounts it with Rack::URLMap.
  def mount_under_script_name!
    self.app = Rack::URLMap.new("/auth" => app)
  end
end
