[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpatryk4815%2FPySteamWeb.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpatryk4815%2FPySteamWeb?ref=badge_shield)

Requirements
============

* Python 3.5+
* pyCrypto
* aiohttp 1.1.6

Instalation
===========

* pip3 install pysteamweb

Usage
=====

.. code-block:: python

    >>> import asyncio
    >>> from pysteamweb import SteamWebBase
    >>>
    >>> async def main():
    >>>     async with SteamWebBase(
    >>>         username='<steam login>',
    >>>         password='<steam password>',
    >>>     ) as s:
    >>>         print('logging success')
    >>>         print(await s.session.send_session(url='http://steamcommunity.com/profiles/{}/edit'.format(s.steam_id), is_post=False))
    >>>
    >>>
    >>> if __name__ == '__main__':
    >>>     loop = asyncio.get_event_loop()
    >>>     loop.run_until_complete(main())
    >>>     loop.close()


Demos
=====

Look at demo folder

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpatryk4815%2FPySteamWeb.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpatryk4815%2FPySteamWeb?ref=badge_large)