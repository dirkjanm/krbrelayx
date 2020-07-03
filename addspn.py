#!/usr/bin/env python
####################
#
# Copyright (c) 2019 Dirk-jan Mollema (@_dirkjan)
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
#
# Add an SPN to a user/computer account via LDAP
#
####################
import sys
import argparse
import ldapdomaindump
import random
import string
import getpass
from ldap3 import NTLM, Server, Connection, ALL
import ldap3
from ldap3.protocol.microsoft import security_descriptor_control

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

def main():
    parser = argparse.ArgumentParser(description='Add an SPN to a user/computer account')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    #maingroup = parser.add_argument_group("Main options")
    parser.add_argument("host", metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to")
    parser.add_argument("-u", "--user", metavar='USERNAME', help="DOMAIN\\username for authentication")
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("-t", "--target", metavar='TARGET', help="Computername or username to target (FQDN or COMPUTER$ name, if unspecified user with -u is target)")
    parser.add_argument("-s", "--spn", required=True, metavar='SPN', help="servicePrincipalName to add (for example: http/host.domain.local or cifs/host.domain.local)")
    parser.add_argument("-r", "--remove", action='store_true', help="Remove the SPN instead of add it")
    parser.add_argument("-q", "--query", action='store_true', help="Show the current target SPNs instead of modifying anything")
    parser.add_argument("-a", "--additional", action='store_true', help="Add the SPN via the msDS-AdditionalDnsHostName attribute")

    args = parser.parse_args()
    #Prompt for password if not set
    authentication = None
    if args.user is not None:
        authentication = NTLM
        if not '\\' in args.user:
            print_f('Username must include a domain, use: DOMAIN\\username')
            sys.exit(1)
        if args.password is None:
            args.password = getpass.getpass()

    controls = security_descriptor_control(sdflags=0x04)
    # define the server and the connection
    s = Server(args.host, get_info=ALL)
    print_m('Connecting to host...')
    c = Connection(s, user=args.user, password=args.password, authentication=authentication)
    print_m('Binding to host')
    # perform the Bind operation
    if not c.bind():
        print_f('Could not bind with specified credentials')
        print_f(c.result)
        sys.exit(1)
    print_o('Bind OK')

    if args.target:
        targetuser = args.target
    else:
        targetuser = args.user.split('\\')[1]

    if '.' in targetuser:
        search = '(dnsHostName=%s)' % targetuser
    else:
        search = '(SAMAccountName=%s)' % targetuser
    c.search(s.info.other['defaultNamingContext'][0], search, controls=controls, attributes=['SAMAccountName', 'servicePrincipalName', 'dnsHostName', 'msds-additionaldnshostname'])

    try:
        targetobject = c.entries[0]
        print_o('Found modification target')
    except IndexError:
        print_f('Target not found!')
        return

    if args.remove:
        operation = ldap3.MODIFY_DELETE
    else:
        operation = ldap3.MODIFY_ADD

    if args.query:
        # If we only want to query it
        print(targetobject)
        return


    if not args.additional:
        c.modify(targetobject.entry_dn, {'servicePrincipalName':[(operation, [args.spn])]})
    else:
        try:
            host = args.spn.split('/')[1]
        except IndexError:
            # Assume this is the hostname
            host = args.spn
        c.modify(targetobject.entry_dn, {'msds-additionaldnshostname':[(operation, [host])]})

    if c.result['result'] == 0:
        print_o('SPN Modified successfully')
    else:
        if c.result['result'] == 50:
            print_f('Could not modify object, the server reports insufficient rights: %s' % c.result['message'])
        elif c.result['result'] == 19:
            print_f('Could not modify object, the server reports a constrained violation')
            if args.additional:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs ending on the domain FQDN)')
            else:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs matching the hostname)')
                print_f('To add any SPN in the current domain, use --additional to add the SPN via the msDS-AdditionalDnsHostName attribute')
        else:
            print_f('The server returned an error: %s' % c.result['message'])


if __name__ == '__main__':
    main()
