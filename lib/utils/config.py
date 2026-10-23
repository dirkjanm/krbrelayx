"""
Config class, mostly extended from ntlmrelayx
"""
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from lib.utils.socksprofiles import get_profile, GENERIC

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

        # LDAP options
        self.dumpdomain = True
        self.addda = True
        self.aclattack = True
        self.validateprivs = True
        self.escalateuser = None
        self.addcomputer = False
        self.delegateaccess = False

        # Custom options
        self.victim = None

        # SOCKS options
        self.runSocks = False
        self.socksHost = '127.0.0.1'
        self.socksPort = 1080
        self.apiPort = 9090
        # Named routing profile applied to relayed sessions when
        # -socks is on. 'generic' means no app-specific behavior.
        self.socksProfile = 'generic'
        # Resolved at config-build time from the chosen profile, with
        # an explicit -socks-login-path overriding it. Empty string
        # means no pre-auth probe.
        self.socksLoginPath = GENERIC['login_path']

    # Make sure we have a fixed version of this to avoid incompatibilities with impacket
    def setLDAPOptions(self, dumpdomain, addda, aclattack, validateprivs, escalateuser, addcomputer, delegateaccess, dumplaps, dumpgmsa, dumpadcs, sid):
        self.dumpdomain = dumpdomain
        self.addda = addda
        self.aclattack = aclattack
        self.validateprivs = validateprivs
        self.escalateuser = escalateuser
        self.addcomputer = addcomputer
        self.delegateaccess = delegateaccess
        self.dumplaps = dumplaps
        self.dumpgmsa = dumpgmsa
        self.dumpadcs = dumpadcs
        self.sid = sid

    def setAuthOptions(self, aeskey, hashes, dcip, password, salt, israwpassword=False):
        self.dcip = dcip
        self.aeskey = aeskey
        self.hashes = hashes
        self.password = password
        self.salt = salt
        self.israwpassword = israwpassword

    def setKrbOptions(self, outformat, victim):
        self.format = outformat
        self.victim = victim

    def setSocksOptions(self, runSocks, socksHost='127.0.0.1', socksPort=1080,
                        apiPort=9090, socksProfile=None, socksLoginPath=None):
        """Configure the SOCKS proxy.

        socksProfile selects a named routing profile (see
        lib/utils/socksprofiles.py). Its login_path is applied unless
        socksLoginPath is given as an explicit override.
        """
        self.runSocks = runSocks
        self.socksHost = socksHost
        self.socksPort = socksPort
        self.apiPort = apiPort
        if socksProfile is not None:
            self.socksProfile = socksProfile
        # Profile defines the default login path; -socks-login-path can
        # override it (None means "leave the profile's value alone").
        profile = get_profile(self.socksProfile)
        self.socksLoginPath = profile['login_path']
        if socksLoginPath is not None:
            self.socksLoginPath = socksLoginPath

    def getSocksProfile(self):
        return get_profile(self.socksProfile)
