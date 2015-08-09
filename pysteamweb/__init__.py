import sys

if sys.version_info < (3, 3):
    raise RuntimeError('You need Python 3.3+ for this module.')

from pysteamweb.steam_base import SteamWebBase
from pysteamweb._steam_id_parser import SteamIdParser

__all__ = [
    'SteamWebBase',
    'SteamIdParser',
]
