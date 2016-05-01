import asyncio

from .. import SteamWebBase


class SteamChat(SteamWebBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.sec_timeout = None
        self.poll_id = None
        self.umq_id = None
        self.message = None

    async def __aenter__(self):
        await super().__aenter__()
        if await self.init_pool():
            return self
        raise ValueError('Init pool error')

    async def close(self):
        await self.del_pool()
        await super().close()

    async def init_pool(self):
        self.sec_timeout = 20
        self.poll_id = 0
        self.umq_id = 0

        result = await self.send_umqid('Logon', {'ui_mode': 'web'}, timeout=35)
        if result['error'] == 'OK':
            self.umq_id = result['umqid']
            self.message = result['message']
            return True
        else:
            return False

    async def del_pool(self):
        await self.send_umqid('Logoff')

    async def get_pool(self):
        self.poll_id += 1

        query_data = {
            'message': self.message,
            'pollid': self.poll_id,
            'sectimeout': self.sec_timeout,
            'secidletime': 0,  # 300 => status change to away
            'use_accountids': 0
        }

        result = await self.send_umqid('Poll', query_data, timeout=self.sec_timeout + 5)
        if result['error'] == 'OK':
            for message in result['messages']:
                # steam_id = int(message['steamid_from'])
                # # if steam_id not in self.friends_list:
                # #     continue
                # if message['type'] == 'personastate':
                #     # old_friend_data = self.friends_list[steam_id].copy()
                #     # self.friends_list[steam_id].update({
                #     #     'm_ePersonaState': message['persona_state'],
                #     #     'm_strName': message['persona_name'],
                #     # })
                #     #
                #     # new_friend_data = self.session.send_session(
                #     #     url='https://steamcommunity.com/chat/friendstate/{}'.format(self.friends_list[steam_id]['m_unAccountID']),
                #     #     is_post=False,
                #     #     is_json=True,
                #     #     timeout=10
                #     # )
                #     # self.friends_list[steam_id].update(new_friend_data)
                #     # self.on_change_status(steam_id, old_friend_data, self.friends_list[steam_id])
                #     pass
                #
                # elif message['type'] == 'saytext':
                #     self.on_message_incoming(steam_id, self.friends_list[steam_id], message['text'])
                # elif message['type'] == 'my_saytext':
                #     self.on_message_sent(steam_id, self.friends_list[steam_id], message['text'])
                # elif message['type'] == 'leftconversation':
                #     self.on_message_left(steam_id, self.friends_list[steam_id])
                asyncio.ensure_future(self.on_message(message))
            self.message = result['messagelast']
        elif result['error'] == 'Timeout':
            if 'sectimeout' in result and result['sectimeout'] > 20:
                self.sec_timeout = result['sectimeout']

            if self.sec_timeout < 120:
                self.sec_timeout = min(self.sec_timeout + 5, 120)

        else:
            raise ConnectionError('pool failed: {}'.format(result))

    async def on_message(self, message):
        pass

    async def send_message(self, steam_id: int, message: str):
        query_data = {
            'type': 'saytext',
            'steamid_dst': steam_id,
            'text': message,
        }

        result = await self.send_umqid('Message', query_data)
        if result['error'] == 'OK':
            return True
        else:
            return False

    async def send_umqid(self, api_type, data=None, timeout=120):
        if data is None:
            data = {}

        url = 'https://api.steampowered.com/ISteamWebUserPresenceOAuth/{}/v0001'.format(api_type)
        data.update({'access_token': self.access_token, 'umqid': self.umq_id})
        try:
            return await self.session.send_request(
                url, data,
                is_post=True, is_json=True, is_ajax=False, referer=None, timeout=timeout
            )
        except asyncio.TimeoutError:
            return {'error': 'Timeout'}

    @classmethod
    def status_friend(cls, friend_data):
        status = friend_data.get('m_ePersonaState')

        if friend_data.get('m_bInGame', False):
            if friend_data.get('m_nInGameAppID', False):
                return 'W grze - ' + friend_data.get('m_strInGameName')
            else:
                return 'W grze spoza Steam - ' + friend_data.get('m_strInGameName')
        else:
            if status == 0:
                return 'Offline'
            elif status == 1:
                return 'Online'
            elif status == 4:
                return 'Drzemka'
            elif status == 3:
                return 'Zaraz wracam'
            elif status == 2:
                return 'Zajęty'
            elif status == 5:
                return 'Chcę się wymienić'
            elif status == 6:
                return 'Chcę pograć'
            else:
                return 'offline'
