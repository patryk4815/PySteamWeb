import re


class SteamIdParser(object):
    def __init__(self, sid):
        self.sid_base = 76561197960265728
        self.sid64 = self._to_64(sid)

    def __str__(self):
        return str(self.sid64)

    def __repr__(self):
        return '<SteamIdParser: {}>'.format(str(self.sid64))

    def _get_type(self, string):
        sid_type = 0
        if isinstance(string, int):
            if string >= self.sid_base:
                sid_type = 1  # sid64
            else:
                sid_type = 2  # account

        elif isinstance(string, str):
            if string.startswith('STEAM_'):
                sid_type = 3  # sid32
            elif re.match(r'\[?U:1:', string):
                sid_type = 4  # steamid3
            else:
                sid_type = 5  # customURL

        return sid_type

    def _to_64(self, sid):
        if isinstance(sid, str) and sid.isdigit():
            sid = int(sid)

        sid_type = self._get_type(sid)
        if sid_type == 1:
            return sid
        elif sid_type == 2:
            return self.sid_base + sid
        elif sid_type == 3:
            match = re.search(r'STEAM_0:([0-1]):(\d+)', sid)
            if match:
                even = int(match.group(1))
                account_half = int(match.group(2))
                return self.sid_base + (account_half * 2) + even
        elif sid_type == 4:
            match = re.search(r'\[?U:1:(\d+)\]?', sid)
            if match:
                account = int(match.group(1))
                return self.sid_base + account
        # elif sid_type == 5:
        #     url = 'http://steamcommunity.com/id/{}'.format(sid)
        #     try:
        #         data = requests.get(url, timeout=5)
        #         match = re.search(r'"steamid":"(\d+)"', data.text)
        #         if match:
        #             return int(match.group(1))
        #     except requests.Timeout:
        #         pass

        raise ValueError('Unknown steam: {}'.format(sid))

    def as_steam64(self):
        return self.as_64()

    def as_64(self):
        return self.sid64

    def as_steam(self):
        return self.as_32()

    def as_32(self):
        acc = self.as_account()
        return 'STEAM_0:{}:{}'.format(acc % 2, acc // 2)

    def as_account(self):
        return self.sid64 & 0xffffffff

    def as_steam3(self):
        return '[U:1:{}]'.format(self.as_account())
    #
    # def as_url(self):
    #     url = 'http://steamcommunity.com/profiles/{}'.format(self.as_64())
    #     try:
    #         data = requests.get(url, timeout=5)
    #         match = re.search(r'https?://steamcommunity\.com/id/(.*?)/', data.url)
    #
    #         return match.group(1) if match is not None else None
    #     except requests.Timeout:
    #         return None
