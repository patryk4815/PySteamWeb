import sys

if sys.version_info < (3, 5):
    raise RuntimeError('You need Python 3.5+ for this module.')

from pysteamweb.steam_base import SteamWebBase
from pysteamweb._steam_id_parser import SteamIdParser
from . import plugins

__all__ = [
    'SteamWebBase',
    'SteamIdParser',
    'plugins',
]
