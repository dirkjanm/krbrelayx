"""
Config class, mostly extended from ntlmrelayx
"""
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

class KrbRelayxConfig(NTLMRelayxConfig):
    def __init__(self):
        NTLMRelayxConfig.__init__(self)

        # Auth options
        self.dcip = None
        self.aeskey = None
        self.hashes = None
        self.password = None
        self.israwpassword = False
        self.salt = None

        # Krb options
        self.format = 'ccache'

    def setAuthOptions(self, aeskey, hashes, dcip, password, salt, israwpassword=False):
        self.dcip = dcip
        self.aeskey = aeskey
        self.hashes = hashes
        self.password = password
        self.salt = salt
        self.israwpassword = israwpassword

    def setKrbOptions(self, outformat):
        self.format = outformat
