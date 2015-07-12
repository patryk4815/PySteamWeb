Requirements
============

* Python 3.4+ (or maybe python 3.3 [not tested])
* pyCrypto
* requests

Instalation
===========

* pip3 install pysteamweb

Usage
=====

.. code-block:: python

    >>> from pysteamweb import SteamWebBase
    >>> 
    >>> steam = SteamWebBase()
    >>> if steam.login(username='steam_login', password='steam_password'):
    >>>     print(steam.send_session(url='http://steamcommunity.com/profiles/{}/edit'.format(steam.steam_id64), is_post=False))
    '....return html string of this url...'