import logging
import time
import hmac
from base64 import b64decode, b64encode
from hashlib import sha1
from bs4 import BeautifulSoup

from .. import SteamWebBase


class _SteamMobileConfirmation(SteamWebBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._two_factor = None
        self._device_id = None
        self.reload_two_factor_config()

    def reload_two_factor_config(self):
        self._two_factor = self.config.load_config('2fa', default=dict())
        self._device_id = self.config.load_config('device', default={
            'device_id': self.generate_device_id(),
        }).get('device_id')

    def generate_device_id(self):
        hash_o = sha1()
        hash_o.update(str(self.steam_id).encode())
        return 'android:{}'.format(hash_o.hexdigest())

    @property
    def device_id(self):
        return self._device_id

    @property
    def identity_secret(self):
        return self._two_factor.get('identity_secret')

    @property
    def shared_secret(self):
        return self._two_factor.get('shared_secret')

    @classmethod
    def generate_auth_code(cls, secret, time_offset=0):
        if isinstance(secret, str):
            secret = b64decode(secret)

        secret_time = int(time.time()) + time_offset

        buffer = []
        buffer.extend([0x00, 0x00, 0x00, 0x00])
        buffer.extend(list(int(secret_time / 30).to_bytes(4, byteorder='big')))

        hmac_str = hmac.new(secret, bytes(buffer), sha1).digest()
        start = hmac_str[19] & 0x0F
        hmac_str = hmac_str[start:start+4]

        full_code = int.from_bytes(bytes(list(hmac_str)[0:4]), byteorder='big') & 0x7fffffff

        chars = '23456789BCDFGHJKMNPQRTVWXY'
        code = ''
        for _ in range(0, 5):
            len_c = len(chars)
            code += chars[full_code % len_c]
            full_code //= len_c

        return code

    @classmethod
    def generate_hash_for_time(cls, secret, time_int, tag):
        buffer = []
        buffer.extend([0x00, 0x00, 0x00, 0x00])
        buffer.extend(list(time_int.to_bytes(4, byteorder='big')))

        if tag:
            buffer.extend(list(tag.encode()))

        return b64encode(hmac.new(b64decode(secret), bytes(buffer), sha1).digest()).decode()

    async def get_confirmations(self, timeout=None):
        data = await self.session.send_session(
            url='https://steamcommunity.com/mobileconf/conf',
            data=self._get_confirmation_query('conf'),
            is_post=False,
            is_json=False,
            is_ajax=False,
            timeout=timeout,
        )
        soup = BeautifulSoup(data)

        confirmations = list()
        for elem in soup.find_all(class_='mobileconf_list_entry'):
            confirmations.append({
                'id': elem.get('data-confid'),
                'key': elem.get('data-key'),
                'descriptions': elem.find(class_='mobileconf_list_entry_description').text,
                'cancel': elem.get('data-cancel'),
                'accept': elem.get('data-accept'),
            })
        return confirmations

    def _get_confirmation_query(self, tag, hash_time=None):
        if hash_time is None:
            hash_time = int(time.time())

        return {
            'p': self.device_id,
            'a': str(self.steam_id),
            'k': self.generate_hash_for_time(self.identity_secret, hash_time, tag),
            't': hash_time,
            'm': 'android',
            'tag': tag,
        }

    async def _send_confirmation(self, url, operation_tag, params=None, timeout=None, hash_time=None):
        if params is None:
            params = {}
        params.update(self._get_confirmation_query(operation_tag, hash_time=hash_time))

        return await self.session.send_session(
            url='https://steamcommunity.com/mobileconf/' + url,
            data=params,
            is_post=False,
            is_json=True,
            is_ajax=False,
            timeout=timeout,
        )

    async def accept_confirmation(self, confirmation_id, confirmation_key, timeout=None, hash_time=None):
        params = {
            'op': 'allow',
            'cid': confirmation_id,
            'ck': confirmation_key,
        }
        return await self._send_confirmation(
            'ajaxop',
            'allow',
            params=params,
            timeout=timeout,
            hash_time=hash_time,
        )

    async def cancel_confirmation(self, confirmation_id, confirmation_key, timeout=None, hash_time=None):
        params = {
            'op': 'cancel',
            'cid': confirmation_id,
            'ck': confirmation_key,
        }
        return await self._send_confirmation(
            'ajaxop',
            'cancel',
            params=params,
            timeout=timeout,
            hash_time=hash_time,
        )

    async def get_confirmation_details(self, confirmation_id, timeout=None, hash_time=None):
        return await self._send_confirmation(
            'details/{}'.format(confirmation_id),
            'details',
            timeout=timeout,
            hash_time=hash_time,
        )

    async def accept_mobile_by_trade_id(self, trade_id):
        for data_confirm in (await self.get_confirmations(timeout=60)):
            logging.info('{}, data_confirm: {}'.format(self.username, data_confirm))

            ret = await self.get_confirmation_details(data_confirm['id'], timeout=20)
            html_data = str(ret.get('html', ''))

            if 'id="tradeofferid_{}"'.format(trade_id) in html_data:
                ret = await self.accept_confirmation(data_confirm['id'], data_confirm['key'], timeout=20)
                logging.info('{}, ret_confirm: {}'.format(self.username, ret))
                # ret_confirm: {'success': True}
                return ret.get('success', False)

        return False


class _SteamActive2fa(_SteamMobileConfirmation):
    async def has_phone(self, timeout=None):
        data = await self.session.send_session(url='https://store.steampowered.com/phone/add', is_json=False, is_ajax=False, is_post=False, timeout=timeout)
        return data.find('javascript:submitPhoneEdit();') != -1

    async def check_phone(self, phone, timeout=None):
        return await self.session.send_session(
            url='https://store.steampowered.com//phone/validate',
            data={
                'phoneNumber': phone,
            },
            is_post=False,
            is_json=True,
            timeout=timeout,
        )

    async def add_phone(self, phone, timeout=None):
        return await self.session.send_session(
            url='https://store.steampowered.com//phone/add_ajaxop',
            data={
                'sessionID': self.session_id,
                'op': 'get_phone_number',
                'input': phone,
                'confirmed': 0,
            },
            is_post=False,
            is_json=True,
            is_ajax=True,
            referer='https://store.steampowered.com/phone/add',
            timeout=timeout,
        )

    async def sms_phone(self, sms_code, timeout=None):
        return await self.session.send_session(
            url='https://store.steampowered.com//phone/add_ajaxop',
            data={
                'sessionID': self.session_id,
                'op': 'get_sms_code',
                'input': sms_code,
                'confirmed': 0,
            },
            is_post=False,
            is_json=True,
            is_ajax=True,
            referer='https://store.steampowered.com/phone/add',
            timeout=timeout,
        )

    async def get_emergency_codes(self, timeout=None):
        await self.session.send_session(
            url='https://store.steampowered.com/twofactor/manage',
            is_post=False,
            is_json=False,
            is_ajax=False,
            timeout=timeout,
        )
        await self.session.send_session(
            url='https://store.steampowered.com/twofactor/manage_action',
            data={
                'sessionid': self.session_id,
                'action': 'emergency',
            },
            is_post=True,
            is_json=False,
            is_ajax=False,
            referer='https://store.steampowered.com/twofactor/manage',
            timeout=timeout,
        )

        auth_code = self.generate_auth_code(self.shared_secret)
        data = await self.session.send_session(
            url='https://store.steampowered.com/twofactor/manage_generate_emergency_codes',
            data={
                'sessionid': self.session_id,
                'authcode': auth_code,
            },
            is_post=True,
            is_json=False,
            is_ajax=False,
            referer='https://store.steampowered.com/twofactor/manage_action',
            timeout=timeout,
        )

        list_codes = list()
        soup = BeautifulSoup(data)
        # <div class="twofactor_settings_instructions twofactor_error">Sorry, that authenticator code was invalid.</div>
        for elem in soup.find_all(class_='twofactor_emergency_code_row'):
            for div in elem.find_all('div'):
                code = div.text
                code = code.strip()
                if len(code) != 7:
                    continue
                list_codes.append(code)
        return list_codes

    async def enable_two_factor(self, timeout=None):
        device_id = self.device_id
        logging.debug('device_id: {}'.format(device_id))

        return await self.session.send_request(
            url='https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v1/',
            data={
                'steamid': self.steam_id.as_64(),
                'access_token': self.access_token,
                'authenticator_time': int(time.time()),
                'authenticator_type': 1,
                'device_identifier': device_id,
                'sms_phone_id': 1,
            },
            is_post=True,
            is_json=True,
            timeout=timeout,
        )

    async def finalize_two_factor(self, shared_secret, sms_code, timeout=None):
        time_diff = 0
        attempts_left = 30

        while True:
            code = self.generate_auth_code(shared_secret, time_diff)
            logging.debug('code: {}'.format(code))

            # {'response': {'want_more': False, 'success': True, 'server_time': '1450040328', 'status': 2}}
            data = await self.session.send_request(
                url='https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v1/',
                data={
                    'steamid': self.steam_id.as_64(),
                    'access_token': self.access_token,
                    'authenticator_code': code,
                    'authenticator_time': int(time.time()),
                    'activation_code': sms_code,
                },
                is_post=True,
                is_json=True,
                timeout=timeout,
            )
            logging.info(data)

            if data.get('response') is None:
                logging.critical(data)
                return False

            if data.get('server_time'):
                time_diff = data['server_time'] - int(time.time())

            if data.get('status') == 89:
                logging.critical(data)
                return False

            elif data.get('want_more', False):
                attempts_left -= 1
                time_diff += 30
                continue  # next loop

            elif data.get('success', False):
                logging.critical(data)
                return False

            else:
                return True


class SteamMobileConfirmation(_SteamActive2fa, _SteamMobileConfirmation):
    pass
