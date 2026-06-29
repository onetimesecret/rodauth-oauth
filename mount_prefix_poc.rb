#!/usr/bin/env ruby
# frozen_string_literal: true

# ---------------------------------------------------------------------------
# Proof of concept: Rack::URLMap mount-prefix mismatch in rodauth-oauth
# (onetimesecret/onetimesecret#3465)
#
# Runs a minimal Rodauth + rodauth-oauth *authorization server* mounted under a
# Rack SCRIPT_NAME ("/auth", via Rack::URLMap), then drives it with Rack::Test
# in two modes that differ ONLY by whether `oauth_mount_prefix "/auth"` is set:
#
#   Mode A  — WITHOUT oauth_mount_prefix   -> reproduces the BUG
#   Mode B  — WITH    oauth_mount_prefix   -> demonstrates the FIX
#
# It checks the three symptoms from the issue / ADR:
#   1. Discovery `issuer`         must include the "/auth" mount point.
#   2. Discovery `token_endpoint` must include the "/auth" mount point.
#   3. A form-encoded POST /auth/token (client Basic auth, NO CSRF token) must
#      be processed, not blocked by CSRF — i.e. the per-feature check_csrf?
#      exemption must line up with the browser-absolute request.path.
#
# In Mode A all three are wrong (bug); in Mode B all three are correct (fix).
# The script prints a PASS/FAIL table for both modes and exits non-zero unless
# Mode A exhibits the bug AND Mode B is fully fixed.
#
# Usage (uses the local lib/ in this repo; no bundler required):
#   ruby mount_prefix_poc.rb
# ---------------------------------------------------------------------------

$LOAD_PATH.unshift File.expand_path("lib", __dir__)

require "json"
require "base64"
require "securerandom"
require "sequel"
require "roda"
require "roda/session_middleware"
require "bcrypt"
require "rack/test"
require "rack/urlmap"
require "rodauth/oauth"

MOUNT = "/auth"
HOST  = "http://example.org"

# --- in-memory schema, reusing the gem's own test migrations -----------------
DB = Sequel.sqlite
Sequel.extension :migration
require "rodauth/migrations"
Sequel::Migrator.run(DB, File.expand_path("test/migrate", __dir__))

def bcrypt(secret)
  BCrypt::Password.create(secret, cost: BCrypt::Engine::MIN_COST)
end

REDIRECT_URI = "https://example.com/callback"
SCOPES       = "user.read user.write"

ACCOUNT_ID = DB[:accounts].insert(email: "foo@example.com", status_id: 2, ph: bcrypt("0123456789"))
APP_ID = DB[:oauth_applications].insert(
  account_id: ACCOUNT_ID,
  name: "PoC App", description: "poc", homepage_url: "https://example.com",
  redirect_uri: REDIRECT_URI,
  client_id: "CLIENT_ID", client_secret: bcrypt("CLIENT_SECRET"),
  scopes: SCOPES
)

# A fresh single-use authorization code for each /token exchange.
def seed_grant(code)
  DB[:oauth_grants].insert(
    oauth_application_id: APP_ID, account_id: ACCOUNT_ID,
    type: "authorization_code", code: code,
    expires_in: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: 300),
    redirect_uri: REDIRECT_URI, scopes: SCOPES
  )
end

# --- minimal authorization-server app ---------------------------------------
def build_app(mount_prefix:)
  app = Class.new(Roda)
  app.plugin :render,
             views: File.expand_path("test/views", __dir__),
             layout_opts: { path: File.expand_path("test/views/layout.str", __dir__) }
  app.plugin(:not_found) { "not found" }
  app.opts[:sessions_convert_symbols] = true
  app.use RodaSessionMiddleware, secret: SecureRandom.random_bytes(64), key: "rack.session"

  mp = mount_prefix
  app.plugin :rodauth, csrf: :route_csrf, json: true do
    enable :login, :logout, :http_basic_auth, :oauth_authorization_code_grant
    db DB
    account_password_hash_column :ph
    hmac_secret "SECRET"
    oauth_application_scopes SCOPES.split
    oauth_grants_token_hash_column nil
    oauth_grants_refresh_token_hash_column nil
    # The whole point of the fix: only set in Mode B.
    oauth_mount_prefix mp if mp
  end

  app.route do |r|
    r.rodauth
    rodauth.load_oauth_server_metadata_route
    r.root { "ok" }
  end
  app
end

# --- Rack::Test driver -------------------------------------------------------
class Driver
  include Rack::Test::Methods
  attr_reader :app

  def initialize(app)
    @app = app
  end
end

def run_mode(mount_prefix:)
  # Wrap the app under a Rack SCRIPT_NAME, exactly like a host app mounting it.
  app    = Rack::URLMap.new(MOUNT => build_app(mount_prefix: mount_prefix))
  driver = Driver.new(app)
  checks = []

  # 1 & 2: discovery metadata under the mount.
  driver.get("#{MOUNT}/.well-known/oauth-authorization-server")
  meta = begin
    JSON.parse(driver.last_response.body)
  rescue StandardError
    {}
  end
  issuer   = meta["issuer"]
  token_ep = meta["token_endpoint"]
  checks << ["discovery issuer includes #{MOUNT}",
             issuer == "#{HOST}#{MOUNT}", "issuer=#{issuer.inspect}"]
  checks << ["discovery token_endpoint includes #{MOUNT}",
             token_ep == "#{HOST}#{MOUNT}/token", "token_endpoint=#{token_ep.inspect}"]

  # 3: form-encoded /token POST with client Basic auth and NO CSRF token.
  code = "CODE-#{SecureRandom.hex(6)}"
  seed_grant(code)
  driver.basic_authorize("CLIENT_ID", "CLIENT_SECRET")
  ok, detail =
    begin
      driver.post("#{MOUNT}/token",
                  "grant_type"   => "authorization_code",
                  "code"         => code,
                  "redirect_uri" => REDIRECT_URI)
      status = driver.last_response.status
      token  = begin
        JSON.parse(driver.last_response.body)["access_token"]
      rescue StandardError
        nil
      end
      [status == 200 && !token.nil?, "status=#{status} access_token=#{token ? 'present' : 'nil'}"]
    rescue Roda::RodaPlugins::RouteCsrf::InvalidToken
      [false, "blocked by CSRF (RouteCsrf::InvalidToken raised)"]
    end
  checks << ["form POST #{MOUNT}/token processed (CSRF-exempt)", ok, detail]

  checks
end

def print_table(title, checks)
  puts title
  checks.each do |name, pass, detail|
    puts format("  [%s] %-48s %s", pass ? "PASS" : "FAIL", name, detail)
  end
  puts
end

puts "=" * 78
puts "rodauth-oauth mount-prefix PoC — server mounted under Rack::URLMap(#{MOUNT.inspect})"
puts "=" * 78
puts

mode_a = run_mode(mount_prefix: nil)       # bug expected
mode_b = run_mode(mount_prefix: MOUNT)     # fix expected

print_table("MODE A — WITHOUT oauth_mount_prefix (expect all FAIL = bug reproduced):", mode_a)
print_table("MODE B — WITH    oauth_mount_prefix #{MOUNT.inspect} (expect all PASS = fix works):", mode_b)

bug_reproduced = mode_a.all? { |_, pass, _| !pass }   # every correctness check fails without the fix
fix_works      = mode_b.all? { |_, pass, _| pass }    # every correctness check passes with the fix

puts "-" * 78
puts "Bug reproduced without the setting : #{bug_reproduced ? 'YES' : 'NO'}"
puts "Fix works with oauth_mount_prefix  : #{fix_works ? 'YES' : 'NO'}"
puts "-" * 78

if bug_reproduced && fix_works
  puts "RESULT: PoC OK — the mount-prefix mismatch is demonstrated and the fix resolves it."
  exit 0
else
  warn "RESULT: PoC FAILED — expected Mode A to exhibit the bug and Mode B to be fully fixed."
  exit 1
end
