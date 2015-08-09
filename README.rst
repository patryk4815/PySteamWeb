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
    >>> with SteamWebBase(username='steam_login', password='steam_password') as steam:
    >>>     print(steam.send_session(url='http://steamcommunity.com/profiles/{}/edit'.format(steam.steam_id64), is_post=False))
    '....return html string of this url...'


Demos
=====

- `Automatic get guardian code from mailbox <https://github.com/patryk4815/PySteamWeb/blob/master/demo/guardian_code_and_pop3.py>`__
