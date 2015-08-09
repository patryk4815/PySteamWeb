import poplib
import time
import re
from pysteamweb import SteamWebBase


class MailIter(object):
    def __init__(self, host, port, ssl, username, password):
        self.mail = None
        if ssl:
            self.mail = poplib.POP3_SSL(host, port=port, timeout=5)
        else:
            self.mail = poplib.POP3(host, port=port, timeout=5)

        self.mail.user(username)
        self.mail.pass_(password)

        self.index = 0
        self.end = self.mail.stat()[0]

    def __iter__(self):
        return self

    def __next__(self):
        if self.index > 0:
            self.mail.dele(self.index)

        self.index += 1
        if self.end >= self.index:
            return b'\n'.join(self.mail.retr(self.index)[1])
        else:
            raise StopIteration()

    def __del__(self):
        if self.mail is not None:
            self.mail.quit()


class SteamWeb(SteamWebBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.email = kwargs.get('email', {})
        self.guardian_code = None  # only for print

    def on_need_guardian(self, kwargs, login_data):
        code = self._get_guardian_code(10, 5)
        kwargs['emailauth'] = code
        self.guardian_code = code  # only for print
        return kwargs

    @staticmethod
    def get_emails(host, port, ssl, username, password):
        return MailIter(host, port, ssl, username, password)

    @staticmethod
    def _get_guardian_from_message(message: bytes) -> str:
        if message.find(b'Access from new device') == -1:
            return None

        match = re.search(
            rb'Here\'s the Steam Guard code you\'ll need to complete the process:  \n\n([A-Z0-9]+?)\n',
            message
        )
        return match.group(1).decode() if match is not None else None

    def _get_guardian_code(self, sleep: int, how_many: int):
        if self.email:
            for _ in range(0, how_many):
                for message in self.get_emails(
                    self.email.get('host'),
                    self.email.get('port'),
                    self.email.get('ssl'),
                    self.email.get('username'),
                    self.email.get('password'),
                ):
                    code = self._get_guardian_from_message(message)
                    if code is not None:
                        return code

                time.sleep(sleep)

        raise ValueError('No guardian code in mailbox')


with SteamWeb(
    username='steam_login',
    password='steam_password',
    email={
        'host': 'pop.gmail.com',
        'port': 995,
        'ssl': True,
        'username': 'username@gmail.com',
        'password': 'password',
    },
) as s:
    print('This is your first login :), And your guardian code is:', s.guardian_code)
