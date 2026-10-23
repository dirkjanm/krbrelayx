"""Routing profiles for the SOCKS HTTP plugin.

A profile is a small dict of target-application-specific knobs. The
plugin reads it per-relay and uses it to decide:

  - login_path:               URL on the target where the AP-REQ is
                              spent at relay setup in exchange for a
                              session cookie. Empty string means no
                              pre-auth probe; the AP-REQ stays in
                              reserve for the first browser request.
  - cookies_never_reinject:   cookie names captured during pre-auth
                              that should NOT be put back on tunneled
                              requests. Used to suppress cookies that
                              identify a server-side handshake context
                              we no longer have access to.
  - stubbed_paths:            exact paths the proxy answers locally
                              with a synthetic 503 instead of forwarding
                              to the target.
  - extra_bypass_prefixes:    additional path prefixes routed off the
                              per-relay lock onto a fresh per-request
                              TCP connection (added on top of the
                              standard static-asset prefixes the plugin
                              already knows about).

Add a profile by appending to PROFILES below. The 'generic' profile is
intentionally empty; it makes the plugin behave as a plain SOCKS proxy
with only the universal static-asset bypass.
"""

GENERIC = {
    'login_path': '',
    'cookies_never_reinject': frozenset(),
    'stubbed_paths': frozenset(),
    'extra_bypass_prefixes': (),
}

GITEA = {
    'login_path': '/user/login?auth_with_sspi=1',
    # The websspi cookie identifies an SSPI handshake context inside the
    # gitea-websspi middleware. Outside the pre-auth window the context
    # is gone server-side, and re-sending the cookie makes the
    # middleware look up a dead session, then fall through to a
    # Negotiate validation that hits the SSPI replay cache.
    'cookies_never_reinject': frozenset({b'websspi'}),
    # Gitea SSE long-poll endpoints. Forwarding them gets a 401 with a
    # session-clearing Set-Cookie; the browser then deletes its session
    # cookie and the next click navigates as anonymous.
    'stubbed_paths': frozenset({
        b'/user/events',
        b'/notifications/sse',
    }),
    'extra_bypass_prefixes': (
        b'/avatars/',
        b'/user/events',
        b'/notifications/sse',
    ),
}

PROFILES = {
    'generic': GENERIC,
    'gitea': GITEA,
}


def get_profile(name):
    """Return the profile dict for `name`, or GENERIC if unknown."""
    return PROFILES.get(name, GENERIC)
