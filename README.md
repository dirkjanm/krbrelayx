# Krbrelayx - Unconstrained delegation abuse toolkit

Toolkit for abusing unconstrained delegation.
Requires [impacket](https://github.com/SecureAuthCorp/impacket) and [ldap3](https://github.com/cannatag/ldap3) to function.
It is recommended to install impacket from git directly to have the latest version available.

More info about this toolkit available in my blog <https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/>

# Tools included
## addspn.py
This tool can add/remove/modify Service Principal Names on accounts in AD over LDAP.

## dnstool.py
Add/modify/delete Active Directory Integrated DNS records via LDAP.

## krbrelayx.py
Given an account with unconstrained delegation privileges, dump Kerberos TGT's of users connecting to hosts similar to ntlmrelayx.

### TODO:
- Specifying SMB as target is not yet complete, it's recommended to run in export mode and then use secretsdump with `-k`
- Conversion tool from/to ccache/kirbi
- SMB1 support in the SMB relay server