Requirements
============

* Python 3.4+ (or maybe python 3.3 [not tested])

Usage
=====

.. code-block:: python

    >>> from steam import SteamWebBase
    >>> 
    >>> steam = SteamWebBase()
    >>> if steam.login(username='steam_login', password='steam_password'):
    >>>     print(steam.send_session(url='http://steamcommunity.com/profiles/{}/edit'.format(steam.steam_id64), is_post=False))
    '....return html string of this url...'