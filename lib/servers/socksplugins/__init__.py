"""Auto-loader for krbrelayx SOCKS plugins.

Each plugin module in this directory must export a `PLUGIN_CLASS` name
pointing at a class that subclasses
`impacket.examples.ntlmrelayx.servers.socksserver.SocksRelay` and exposes
`PLUGIN_NAME` and `PLUGIN_SCHEME` class attributes.
"""
import os
import sys
from importlib.resources import files

KRB_SOCKS_RELAYS = set()

_pkg_path = files('lib.servers').joinpath('socksplugins')
for _entry in _pkg_path.iterdir():
    name = _entry.name
    if name.startswith('__') or not name.endswith('.py'):
        continue
    modname = __package__ + '.' + os.path.splitext(name)[0]
    __import__(modname)
    module = sys.modules[modname]
    plugin_attr = getattr(module, 'PLUGIN_CLASS', None)
    if plugin_attr is None:
        continue
    KRB_SOCKS_RELAYS.add(getattr(module, plugin_attr))
