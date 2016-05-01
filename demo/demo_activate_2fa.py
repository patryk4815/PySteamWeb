import logging
import asyncio

logging.basicConfig(level=logging.DEBUG)

from pysteamweb import SteamWebBase
from pysteamweb.plugins import *


class SteamMixin(SteamMobileConfirmation, SteamWebBase):
    def on_need_guardian(self, kwargs, login_data):
        kwargs['emailauth'] = input('Enter guardian code: ')
        return kwargs

    def on_need_twofactor(self, kwargs, login_data):
        if not self.shared_secret:
            raise ValueError('You dont have two_factor in script!')
        else:
            kwargs['twofactorcode'] = self.generate_auth_code(self.shared_secret)
        return kwargs

    async def init_two_factor(self, phone):
        print('start init two factor')
        has_phone = await self.has_phone()
        if not has_phone:
            data = await self.check_phone(phone)

            print('check_phone', data)
            if data.get('is_valid'):
                data = await self.add_phone(phone)
                print('add_phone', data)

                if data.get('success'):
                    data = await self.sms_phone(input('Enter sms code: '))
                    print('sms_phone', data)
                else:
                    print('sms not send - invalid token or data')
            else:
                print('phone not valid...')
                raise ValueError()

            has_phone = await self.has_phone()

        if not has_phone:
            raise ValueError('not phone')

        is_finalize = False
        data = await self.enable_two_factor()
        print(data)

        status = data.get('response', {}).get('status')
        if status == 1:
            self.config.save_config('2fa', data['response'])
            self.reload_two_factor_config()
            is_finalize = await self.finalize_two_factor(data['response']['shared_secret'], input('sms code: '))

        if status == 29 or is_finalize:
            codes = await self.get_emergency_codes()
            print(codes)
            self.config.save_config('codes_backup', codes)
            print('you have finalize_two_factor INSTALLED!')
        elif is_finalize:
            print('finalize_two_factor DONE!')
        else:
            print('finalize_two_factor FAILED!')


async def main():
    async with SteamMixin(
        username='<steam login>',
        password='<steam password>',
    ) as s:
        print('logging success')
        await s.init_two_factor('<phone number>')  # your phone like +48666555444


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
