import json
import os
import re
import logging
from base64 import b64encode
from binascii import hexlify

import asyncio
from urllib.parse import urlsplit

import aiohttp
from aiohttp.cookiejar import URL

from http.cookies import Morsel
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

from ._steam_id_parser import SteamIdParser


def request_as_mobile(func):
    mobile_headers = {
        "X-Requested-With": "com.valvesoftware.android.steam.community",
        "Referer": "https://steamcommunity.com/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client",
        "User-Agent": "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "Accept": "text/javascript, text/html, application/xml, text/xml, */*"
    }

    def _add_cookie(_self):
        _self.set_cookies({
            'mobileClientVersion': '0 (2.1.3)',
            'mobileClient': 'android',
        })

    def _remove_cookie(_self):
        _self.del_cookie('mobileClientVersion')
        _self.del_cookie('mobileClient')

    async def _inner(self, *args, **kwargs):
        if not kwargs.get('headers'):
            kwargs['headers'] = mobile_headers.copy()

        _add_cookie(self)
        ret = await func(self, *args, **kwargs)
        _remove_cookie(self)
        return ret

    return _inner


class SessionBase(object):
    def __init__(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()

        self._loop = loop
        self._session = aiohttp.ClientSession(loop=loop, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/45.0.2453.0 Safari/537.36'
        })

    def close(self):
        self._session.close()

    def _get_domain_for_request_url(self, response_url):
        url_parsed = urlsplit(response_url or "")
        hostname = url_parsed.hostname
        return hostname if hostname else ''

    def clear(self):
        self._session.cookie_jar.clear()

    def del_cookie(self, name, response_url=None):
        cookies = self._session.cookie_jar._cookies
        domain = self._get_domain_for_request_url(response_url)
        if domain in cookies:
            cookies[domain].pop(name, None)

    def set_cookies(self, cookies, response_url=None):
        self._session.cookie_jar.update_cookies(cookies, response_url=URL(response_url if response_url else ''))

    def get_cookies(self, response_url='http://steamcommunity.com'):
        global_domain = self._get_domain_for_request_url(response_url)

        ret = dict()
        for cookie in self._session.cookie_jar:
            domain = cookie.get('domain')
            value = cookie.value

            ret.setdefault(domain if domain else '', dict()).setdefault(
                cookie.key,
                value
            )

        ret2 = dict()
        ret2.update(ret.get('', dict()))  # first get shared
        ret2.update(ret.get(global_domain, dict()))

        return ret2

    async def _request(self, module, url, data=None,
                       is_post=True, is_json=False, is_ajax=False,
                       referer=None, timeout=120, headers=None):
        if data is None:
            data = {}
        if timeout is None:
            timeout = 600

        headers_param = {}
        if referer is not None:
            headers_param['Referer'] = referer
        if is_ajax:
            headers_param['X-Requested-With'] = 'XMLHttpRequest'
        if headers is not None:
            headers_param = headers.copy()

        with aiohttp.Timeout(timeout):  # TODO: rewrite timeout to new structure
            if is_post:
                r = await module.post(url, data=data, headers=headers_param)
                if is_json:
                    ret = await r.json()
                else:
                    ret = (await r.read()).decode()  # fixme
                r.close()
                if self._session != module:  # fixme
                    module.close()
            else:
                r = await module.get(url, params=data, headers=headers_param)
                if is_json:
                    ret = await r.json()
                else:
                    ret = (await r.read()).decode()  # fixme
                r.close()
                if self._session != module:  # fixme
                    module.close()
        return ret

    async def send_request(self, url, data=None, is_post=True, is_json=False, is_ajax=False, referer=None, timeout=120, headers=None):
        return await self._request(aiohttp.ClientSession(), url, data, is_post, is_json, is_ajax, referer, timeout, headers=headers)

    async def send_session(self, url, data=None, is_post=True, is_json=False, is_ajax=False, referer=None, timeout=120, headers=None):
        # try:
        return await self._request(self._session, url, data, is_post, is_json, is_ajax, referer, timeout, headers=headers)
        # except ValueError as e:
        #     if str(e) == 'Can redirect only to http or https: steammobile':
        #         self.on_session_expire()
        #     pass

    @request_as_mobile
    async def _request_mobile(self, *args, **kwargs):
        return await self._request(*args, **kwargs)

    async def send_mobile_request(self, url, data=None, is_post=True, is_json=False, is_ajax=False, referer=None, timeout=120, headers=None):
        return await self._request_mobile(aiohttp.ClientSession(), url, data, is_post, is_json, is_ajax, referer, timeout, headers=headers)

    async def send_mobile_session(self, url, data=None, is_post=True, is_json=False, is_ajax=False, referer=None, timeout=120, headers=None):
        return await self._request_mobile(self._session, url, data, is_post, is_json, is_ajax, referer, timeout, headers=headers)


class ConfigBase(object):
    def __init__(self, username):
        self.username = username

    def _read_config_data(self, filename):
        config_path = os.path.join(os.path.expanduser("~"), '.steam_py', filename + ".config")
        if not os.path.exists(config_path):
            return None

        return open(config_path, 'rt').read()

    def _write_config_data(self, filename, data):
        config_path = os.path.join(os.path.expanduser("~"), '.steam_py', filename + ".config")
        dir_name = os.path.dirname(config_path)
        os.makedirs(dir_name, exist_ok=True)

        open(config_path, 'wt').write(data)

    def load_config(self, suffix, default=None):
        data = self._read_config_data('{}_{}'.format(self.username, suffix))
        if isinstance(data, str):
            return json.loads(data)
        elif isinstance(data, dict):
            return data
        return default

    def save_config(self, suffix, data):
        if not isinstance(data, (list, dict)):
            raise AttributeError('data must be list or dict')

        self._write_config_data('{}_{}'.format(self.username, suffix), json.dumps(data))

    def whitelist_cookie(self, name):
        whitelists = [
            r'^steamLogin$',
            r'^steamLoginSecure$',
            r'^steamMachineAuth\d+$',  # quardian secret code
            r'^steamRememberLogin$'
        ]
        for regex in whitelists:
            if re.match(regex, name) is not None:
                return True
        return False


class SteamWebBase(object):
    @classmethod
    def encrypt_password(cls, password, mod, exp):
        rsa_obj = RSA.construct((
            int.from_bytes(bytearray.fromhex(mod), byteorder='big'),
            int.from_bytes(bytearray.fromhex(exp), byteorder='big'),
        ))

        cipher = PKCS1_v1_5.new(rsa_obj)
        return b64encode(cipher.encrypt(password.encode('utf-8'))).decode()

    @classmethod
    def generate_session_id(cls):
        return hexlify(Random.get_random_bytes(12)).decode()

    def __init__(self, *args, **kwargs):
        loop = kwargs.get('loop')
        if loop is None:
            self._loop = asyncio.get_event_loop()
        else:
            self._loop = loop

        self._session_id = None
        self.steam_id = None
        self.access_token = None

        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.session = SessionBase(loop=self._loop)
        self.config = ConfigBase(self.username)

        # init_auth_guardian = kwargs.get('init_cookies')
        # if init_auth_guardian:
        #     self.session.set_cookies(init_auth_guardian)

    def read_cookies(self):
        return self.config.load_config('cookies', default=dict())

    def write_cookie(self):
        data = self.session.get_cookies()
        data_return = {}
        for key, value in data.items():
            if self.config.whitelist_cookie(key):
                data_return[key] = value

        if not data_return:
            return
        self.config.save_config('cookies', data_return)

    @property
    def session_id(self):
        if self._session_id:
            return self._session_id

        cookies = self.session.get_cookies()
        session = cookies.get('sessionid')
        if not session:
            session = self.generate_session_id()
            self.session.set_cookies({'sessionid': session})

        self._session_id = session
        return session

    async def _check_is_login(self):
        _ = self.session_id  # gen session id
        chat_html = await self.session.send_session(
            url='https://steamcommunity.com/chat/',
            is_post=False
        )

        if chat_html.find('g_steamID = false;') > -1:  # not login
            logging.debug('chat_html g_steamID = false')
            return False

        try:
            self.steam_id = SteamIdParser(int(re.search(r'g_steamID = "(.*?)";', chat_html).group(1)))

            self.access_token = re.search(r'WebAPI = new CWebAPI\( \'.*?\', \'.*?\', "(.*?)" \);', chat_html).group(1)

            logging.info('self.session_id = {}'.format(self.session_id))
            logging.info('self.steam_id64 = {}'.format(self.steam_id))
            logging.info('self.access_token = {}'.format(self.access_token))
        except AttributeError:
            logging.debug('_check_is_login AttributeError')
            return False

        return True

    async def _check_mobile_is_login(self):
        _ = self.session_id  # gen session id
        chat_html = await self.session.send_session(
            url='http://steamcommunity.com/market/',
            is_post=False
        )
        if chat_html.find('g_steamID = false;') > -1:  # not login
            logging.debug('chat_html g_steamID = false')
            logging.debug(self.session.get_cookies())
            return False

        if not self.access_token:
            logging.debug('self.access_token is None, need re-login!')
            return False

        try:
            self.steam_id = SteamIdParser(int(re.search(r'g_steamID = "(.*?)";', chat_html).group(1)))

            logging.info('self.session_id = {}'.format(self.session_id))
            logging.info('self.steam_id64 = {}'.format(self.steam_id))
            logging.info('self.access_token = {}'.format(self.access_token))
        except AttributeError:
            logging.debug('_check_is_login AttributeError')
            return False

        return True

    async def _login(self, **kwargs):
        query_data = {
            'username': '',
            'password': '',
            'emailauth': '',            # kod guardian (guardian)
            'loginfriendlyname': '',    # przyjazna nazwa (guardian)
            'captchagid': '-1',           # https://store.steampowered.com/join/refreshcaptcha/
            'captcha_text': '',         # https://store.steampowered.com/public/captcha.php?gid=gid
            'emailsteamid': '',         # jezeli podajemy guardiana to trzeba tez to podac (guardian)
            'rsatimestamp': 0,
            'remember_login': False,
            'twofactorcode': '',
        }
        query_data.update(dict(kwargs))

        self.session.set_cookies(self.read_cookies())
        if await self._check_is_login():
            return True

        rsa_data = await self.session.send_request(
            url='https://steamcommunity.com/login/getrsakey/',
            data={'username': query_data.get('username')},
            is_post=True,
            is_json=True
        )
        if not rsa_data.get('success'):
            return False

        query_data['rsatimestamp'] = rsa_data.get('timestamp')
        query_data['password'] = self.encrypt_password(
            query_data.get('password'),
            rsa_data.get('publickey_mod'),
            rsa_data.get('publickey_exp')
        )

        logging.info('pre cookies dologin: {}'.format(self.session.get_cookies()))
        login_data = await self.session.send_session(
            url='https://steamcommunity.com/login/dologin/',
            data=query_data,
            is_post=True,
            is_json=True
        )
        cookies = self.session.get_cookies()
        logging.info('post cookies dologin: {}'.format(cookies))
        logging.info('post result dologin: {}'.format(login_data))

        # self.session_clear()
        # self.session_set_cookies(cookies)

        if not login_data.get('success', False):
            if login_data.get('emailauth_needed', False):
                kwargs['emailsteamid'] = login_data['emailsteamid']
                # kwargs['loginfriendlyname'] = input('Enter device name: ')

                kwargs = self.on_need_guardian(kwargs, login_data)
                return await self._login(**kwargs)

            elif login_data.get('captcha_needed', False):
                kwargs['captchagid'] = login_data['captcha_gid']
                kwargs = self.on_need_captcha(kwargs, login_data)
                return await self._login(**kwargs)

            elif login_data.get('requires_twofactor', False):
                kwargs = self.on_need_twofactor(kwargs, login_data)
                return await self._login(**kwargs)

            return False

        if query_data.get('remember_login'):
            pass

        if await self._check_is_login():
            self.write_cookie()
            return True

        return False

    async def _mobile_login(self, **kwargs):
        query_data = {
            'username': '',
            'password': '',
            'emailauth': '',            # kod guardian (guardian)
            'loginfriendlyname': '',    # przyjazna nazwa (guardian)
            'captchagid': '-1',           # https://store.steampowered.com/join/refreshcaptcha/
            'captcha_text': '',         # https://store.steampowered.com/public/captcha.php?gid=gid
            'emailsteamid': '',         # jezeli podajemy guardiana to trzeba tez to podac (guardian)
            'rsatimestamp': 0,
            'remember_login': False,
            'twofactorcode': '',
            'oauth_client_id': 'DE45CD61',
            'oauth_scope': 'read_profile write_profile read_client write_client',
        }
        query_data.update(dict(kwargs))

        self.session.set_cookies(self.read_cookies())
        self.access_token = self.config.load_config('oauth', default=dict()).get('token', None)
        if await self._check_mobile_is_login():
            return True

        rsa_data = await self.session.send_mobile_request(
            url='https://steamcommunity.com/login/getrsakey/',
            data={'username': query_data.get('username')},
            is_post=True,
            is_json=True,
        )
        if not rsa_data.get('success'):
            logging.debug('rsa_data is False')
            return False

        query_data['rsatimestamp'] = rsa_data.get('timestamp')
        query_data['password'] = self.encrypt_password(
            query_data.get('password'),
            rsa_data.get('publickey_mod'),
            rsa_data.get('publickey_exp')
        )

        logging.info('pre cookies dologin: {}'.format(self.session.get_cookies()))
        login_data = await self.session.send_mobile_session(
            url='https://steamcommunity.com/login/dologin/',
            data=query_data,
            is_post=True,
            is_json=True,
        )
        cookies = self.session.get_cookies()
        logging.info('post cookies dologin: {}'.format(cookies))
        logging.info('post result dologin: {}'.format(login_data))

        if not login_data.get('success', False):
            if login_data.get('emailauth_needed', False):
                kwargs['emailsteamid'] = login_data['emailsteamid']
                # kwargs['loginfriendlyname'] = input('Enter device name: ')

                kwargs = self.on_need_guardian(kwargs, login_data)
                return await self._mobile_login(**kwargs)

            elif login_data.get('captcha_needed', False):
                kwargs['captchagid'] = login_data['captcha_gid']
                kwargs = self.on_need_captcha(kwargs, login_data)
                return await self._mobile_login(**kwargs)

            elif login_data.get('requires_twofactor', False):
                kwargs = self.on_need_twofactor(kwargs, login_data)
                return await self._mobile_login(**kwargs)

            return False

        if query_data.get('remember_login'):
            pass

        oauth = json.loads(login_data['oauth'])
        self.access_token = oauth['oauth_token']

        # set cookies, too be sure :)
        cookies = self.session.get_cookies()
        self.session.clear()
        self.session.set_cookies(cookies)

        if await self._check_mobile_is_login():
            self.config.save_config('oauth', {'token': self.access_token})
            self.write_cookie()
            return True

        return False

    def on_need_guardian(self, kwargs, login_data):
        # kwargs['emailauth'] = input('Enter guardian code: ')
        raise NotImplementedError('on_need_guardian')

    def on_need_captcha(self, kwargs, login_data):
        # kwargs['captcha_text'] = input(
        #     'Enter captcha from url '
        #     'https://store.steampowered.com/public/captcha.php?gid={} : '.format(login_data['captcha_gid'])
        # )
        raise NotImplementedError('on_need_captcha')

    def on_need_twofactor(self, kwargs, login_data):
        # kwargs['twofactorcode'] = input('Enter twofactor code: ')
        raise NotImplementedError('on_need_twofactor')

    async def close(self):
        self.session.close()

    async def __aenter__(self):
        if await self._mobile_login(username=self.username, password=self.password):  # fixme
            return self
        raise ValueError('not logged in')

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

