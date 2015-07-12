from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from base64 import b64encode
import requests
import json
import os
import re

import logging
# logging.basicConfig(level=logging.INFO)


class SteamWebBase(object):
    @staticmethod
    def encrypt_password(password, mod, exp):
        rsa_obj = RSA.construct((
            int.from_bytes(bytearray.fromhex(mod), byteorder='big'),
            int.from_bytes(bytearray.fromhex(exp), byteorder='big'),
        ))

        cipher = PKCS1_v1_5.new(rsa_obj)
        return b64encode(cipher.encrypt(password.encode('utf-8')))

    def __init__(self):
        self.session = self._init_session()

    def _init_session(self):
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/45.0.2453.0 Safari/537.36'
        })
        return session

    def session_set_cookies(self, cookies):
        self.session.cookies.update(cookies)

    def session_get_cookies(self):
        return dict(self.session.cookies)

    def _request(self, module, url, data=None, is_post=True, is_json=False, is_ajax=False, referer=None, timeout=120):
        if data is None:
            data = {}

        headers = {}
        if referer is not None:
            headers['Referer'] = referer
        if is_ajax:
            headers['X-Requested-With'] = 'XMLHttpRequest'

        if is_post:
            response = module.post(url, data=data, timeout=timeout, headers=headers)
        else:
            response = module.get(url, params=data, timeout=timeout, headers=headers)

        if is_json:
            return response.json()
        else:
            return response.text

    def send_request(self, url, data=None, is_post=True, is_json=False, is_ajax=False, referer=None, timeout=120):
        return self._request(requests, url, data, is_post, is_json, is_ajax, referer, timeout)

    def send_session(self, url, data=None, is_post=True, is_json=False, is_ajax=False, referer=None, timeout=120):
        return self._request(self.session, url, data, is_post, is_json, is_ajax, referer, timeout)

    def _check_is_login(self):
        chat_html = self.send_session(
            url='http://steamcommunity.com/chat/',
            is_post=False
        )

        if chat_html.find('g_steamID = false;') > -1:  # not login
            return False

        try:
            self.session_id = re.search(r'g_sessionID = "(.*?)";', chat_html).group(1)
            self.steam_id64 = int(re.search(r'g_steamID = "(.*?)";', chat_html).group(1))

            self.access_token = re.search(r'WebAPI = new CWebAPI\( \'.*?\', \'.*?\', "(.*?)" \);', chat_html).group(1)
            self.friends_list = json.loads(re.search(r'Chat = new CWebChat\( WebAPI, {[^}]*?},'
                                                     r' (\[.*\]), \[.*\] \);', chat_html).group(1))

            self.friends_list = {int(key['m_ulSteamID']): key for key in self.friends_list}
        except AttributeError:
            return False

        logging.info(self.session_get_cookies())
        return True

    def _read_config_data(self, username):
        config_path = os.path.join(os.path.expanduser("~"), '.steam_py', username + ".config")
        if not os.path.exists(config_path):
            return None

        return open(config_path, 'rt').read()

    def read_cookies(self, username):
        data = self._read_config_data(username)
        if isinstance(data, str):
            return json.loads(data)
        elif isinstance(data, dict):
            return data

        return {}

    def _write_config_data(self, username, data):
        config_path = os.path.join(os.path.expanduser("~"), '.steam_py', username + ".config")
        dir_name = os.path.dirname(config_path)
        os.makedirs(dir_name, exist_ok=True)

        open(config_path, 'wt').write(data)

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

    def write_cookie(self, username):
        data = self.session_get_cookies()
        data_return = {}
        for key, value in data.items():
            if self.whitelist_cookie(key):
                data_return[key] = value

        if not data_return:
            return

        self._write_config_data(username, json.dumps(data_return))

    def login(self, **kwargs):
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
            'twofactorcode': '',  # ??
        }
        query_data.update(dict(kwargs))

        cookies_read = self.read_cookies(query_data.get('username'))
        self.session_set_cookies(cookies_read)

        if self._check_is_login():
            return True

        rsa_data = self.send_request(
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

        logging.info(self.session_get_cookies())
        login_data = self.send_session(
            url='https://steamcommunity.com/login/dologin/',
            data=query_data,
            is_post=True,
            is_json=True
        )
        logging.info(self.session_get_cookies())
        logging.info(login_data)

        if not login_data.get('success', False):
            if login_data.get('emailauth_needed', False):
                kwargs['emailauth'] = input('Podaj haslo quardian z emaila: ')
                # kwargs['loginfriendlyname'] = input('Podaj nazwe urzadzenia: ')
                kwargs['emailsteamid'] = login_data['emailsteamid']

                return self.login(**kwargs)

            elif login_data.get('captcha_needed', False):
                kwargs['captchagid'] = login_data['captcha_gid']
                kwargs['captcha_text'] = input('Podaj kod z obrazka '
                                               'https://store.steampowered.com/public/captcha.php'
                                               '?gid={} : '.format(login_data['captcha_gid']))

                return self.login(**kwargs)

            return False

        if query_data.get('remember_login'):
            pass

        if self._check_is_login():
            self.write_cookie(query_data.get('username'))
            return True

        return False
