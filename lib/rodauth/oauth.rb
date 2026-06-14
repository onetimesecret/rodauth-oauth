# frozen_string_literal: true

require "rodauth"
require "rodauth/oauth/version"

module Rodauth
  module OAuth
    module FeatureExtensions
      def auth_server_route(name, *args, &blk)
        routes = route(name, *args, &blk)

        # Rodauth's +route+ macro generates +#{name}_path+/+#{name}_url+ off
        # +route_path+, which is built from +prefix+ and +base_url+ — neither of
        # which reflects a Rack +SCRIPT_NAME+ mount point (e.g. +Rack::URLMap+).
        # Re-generate the OAuth endpoint helpers so they also honor
        # +oauth_mount_prefix+, keeping discovery-metadata URLs and the
        # per-feature +check_csrf?+ +request.path+ comparisons aligned with the
        # browser-absolute path. Route *matching* (which uses +remaining_path+)
        # is untouched, and non-OAuth Rodauth routes keep the stock helpers.
        # With the default empty +oauth_mount_prefix+ these are equivalent to
        # the originals.
        route_meth = :"#{name}_route"
        define_method(:"#{name}_path") do |opts = {}|
          segment = send(route_meth)
          "#{oauth_mount_prefix}#{route_path(segment, opts)}" if segment
        end
        define_method(:"#{name}_url") do |opts = {}|
          segment = send(route_meth)
          "#{base_url}#{oauth_mount_prefix}#{route_path(segment, opts)}" if segment
        end

        handle_meth = routes.last

        define_method(:"#{handle_meth}_for_auth_server") do
          next unless is_authorization_server?

          send(:"#{handle_meth}_not_for_auth_server")
        end

        alias_method :"#{handle_meth}_not_for_auth_server", handle_meth
        alias_method handle_meth, :"#{handle_meth}_for_auth_server"

        # make all requests usable via internal_request feature
        internal_request_method name
      end

      # override
      def translatable_method(meth, value)
        define_method(meth) { |*args| translate(meth, value, *args) }
        auth_value_methods(meth)
      end
    end
  end

  Feature.prepend OAuth::FeatureExtensions
end

require "rodauth/oauth/railtie" if defined?(Rails)
