# Krbrelayx - Unconstrained delegation abuse toolkit

Toolkit for abusing unconstrained delegation.
Requires [impacket](https://github.com/SecureAuthCorp/impacket) and [ldap3](https://github.com/cannatag/ldap3) to function.
It is recommended to install impacket from git directly to have the latest version available.

More info about this toolkit available in my blog <https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/>

# Tools included
## addspn.py
This tool can add/remove/modify Service Principal Names on accounts in AD over LDAP.
```
usage: addspn.py [-h] [-u USERNAME] [-p PASSWORD] [-t TARGET] -s SPN [-r] [-q]
                 [-a]
                 HOSTNAME

Add an SPN to a user/computer account

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to
                        connect to

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username for authentication
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified
  -t TARGET, --target TARGET
                        Computername or username to target (FQDN or COMPUTER$
                        name, if unspecified user with -u is target)
  -s SPN, --spn SPN     servicePrincipalName to add (for example:
                        http/host.domain.local or cifs/host.domain.local)
  -r, --remove          Remove the SPN instead of add it
  -q, --query           Show the current target SPNs instead of modifying
                        anything
  -a, --additional      Add the SPN via the msDS-AdditionalDnsHostName
                        attribute
```

## dnstool.py
Add/modify/delete Active Directory Integrated DNS records via LDAP.
```
usage: dnstool.py [-h] [-u USERNAME] [-p PASSWORD] [--forest] [--zone ZONE]
                  [--print-zones] [-r TARGETRECORD]
                  [-a {add,modify,query,remove,ldapdelete}] [-t {A}]
                  [-d RECORDDATA] [--allow-multiple] [--ttl TTL]
                  HOSTNAME

Query/modify DNS records for Active Directory integrated DNS via LDAP

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to
                        connect to

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username for authentication.
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified
  --forest              Search the ForestDnsZones instead of DomainDnsZones
  --zone ZONE           Zone to search in (if different than the current
                        domain)
  --print-zones         Only query all zones on the DNS server, no other
                        modifications are made

Record options:
  -r TARGETRECORD, --record TARGETRECORD
                        Record to target (FQDN)
  -a {add,modify,query,remove,ldapdelete}, --action {add,modify,query,remove,ldapdelete}
                        Action to perform. Options: add (add a new record),
                        modify (modify an existing record), query (show
                        existing), remove (mark record for cleanup from DNS
                        cache), delete (delete from LDAP). Default: query
  -t {A}, --type {A}    Record type to add (Currently only A records
                        supported)
  -d RECORDDATA, --data RECORDDATA
                        Record data (IP address)
  --allow-multiple      Allow multiple A records for the same name
  --ttl TTL             TTL for record (default: 180)
```

## printerbug.py
Simple tool to trigger SpoolService bug via RPC backconnect. Similar to [dementor.py](https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc). Thanks to @agsolino for implementing these RPC calls.

```
usage: printerbug.py [-h] [-target-file file] [-port [destination port]]
                     [-hashes LMHASH:NTHASH] [-no-pass]
                     target attackerhost

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  attackerhost          hostname to connect to

optional arguments:
  -h, --help            show this help message and exit

connection:
  -target-file file     Use the targets in the specified file instead of the
                        one on the command line (you must still specify
                        something as target name)
  -port [destination port]
                        Destination port to connect to SMB Server

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful when proxying through
                        ntlmrelayx)

```

## krbrelayx.py
Given an account with unconstrained delegation privileges, dump Kerberos TGT's of users connecting to hosts similar to ntlmrelayx.

```
usage: krbrelayx.py [-h] [-debug] [-t TARGET] [-tf TARGETSFILE] [-w]
                    [-ip INTERFACE_IP] [-r SMBSERVER] [-l LOOTDIR]
                    [-f {ccache,kirbi}] [-codec CODEC] [-no-smb2support]
                    [-wh WPAD_HOST] [-wa WPAD_AUTH_NUM] [-6] [-p PASSWORD]
                    [-hp HEXPASSWORD] [-s USERNAME] [-hashes LMHASH:NTHASH]
                    [-aesKey hex key] [-dc-ip ip address] [-e FILE]
                    [-c COMMAND] [--enum-local-admins] [--no-dump] [--no-da]
                    [--no-acl] [--no-validate-privs]
                    [--escalate-user ESCALATE_USER]

Kerberos "relay" tool. Abuses accounts with unconstrained delegation to pwn
things.

Main options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -t TARGET, --target TARGET
                        Target to attack, since this is Kerberos, only
                        HOSTNAMES are valid. Example: smb://server:445 If
                        unspecified, will store tickets for later use.
  -tf TARGETSFILE       File that contains targets by hostname or full URL,
                        one per line
  -w                    Watch the target file for changes and update target
                        list automatically (only valid with -tf)
  -ip INTERFACE_IP, --interface-ip INTERFACE_IP
                        IP address of interface to bind SMB and HTTP servers
  -r SMBSERVER          Redirect HTTP requests to a file:// path on SMBSERVER
  -l LOOTDIR, --lootdir LOOTDIR
                        Loot directory in which gathered loot (TGTs or dumps)
                        will be stored (default: current directory).
  -f {ccache,kirbi}, --format {ccache,kirbi}
                        Format to store tickets in. Valid: ccache (Impacket)
                        or kirbi (Mimikatz format) default: ccache
  -codec CODEC          Sets encoding used (codec) from the target's output
                        (default "ascii"). If errors are detected, run
                        chcp.com at the target, map the result with
                        https://docs.python.org/2.4/lib/standard-
                        encodings.html and then execute ntlmrelayx.py again
                        with -codec and the corresponding codec
  -no-smb2support       Disable SMB2 Support
  -wh WPAD_HOST, --wpad-host WPAD_HOST
                        Enable serving a WPAD file for Proxy Authentication
                        attack, setting the proxy host to the one supplied.
  -wa WPAD_AUTH_NUM, --wpad-auth-num WPAD_AUTH_NUM
                        Prompt for authentication N times for clients without
                        MS16-077 installed before serving a WPAD file.
  -6, --ipv6            Listen on both IPv6 and IPv4

Kerberos Keys (of your account with unconstrained delegation):
  -p PASSWORD, --krbpass PASSWORD
                        Account password
  -hp HEXPASSWORD, --krbhexpass HEXPASSWORD
                        Hex-encoded password
  -s USERNAME, --krbsalt USERNAME
                        Case sensitive (!) salt. Used to calculate Kerberos
                        keys.Only required if specifying password instead of
                        keys.
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter

SMB attack options:
  -e FILE               File to execute on the target system. If not
                        specified, hashes will be dumped (secretsdump.py must
                        be in the same directory)
  -c COMMAND            Command to execute on target system. If not specified,
                        hashes will be dumped (secretsdump.py must be in the
                        same directory).
  --enum-local-admins   If relayed user is not admin, attempt SAMR lookup to
                        see who is (only works pre Win 10 Anniversary)

LDAP attack options:
  --no-dump             Do not attempt to dump LDAP information
  --no-da               Do not attempt to add a Domain Admin
  --no-acl              Disable ACL attacks
  --no-validate-privs   Do not attempt to enumerate privileges, assume
                        permissions are granted to escalate a user via ACL
                        attacks
  --escalate-user ESCALATE_USER
                        Escalate privileges of this user instead of creating a
                        new one
```

### TODO:
- Specifying SMB as target is not yet complete, it's recommended to run in export mode and then use secretsdump with `-k`
- Conversion tool from/to ccache/kirbi
- SMB1 support in the SMB relay server