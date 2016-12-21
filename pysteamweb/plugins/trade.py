import logging
import time
import re
import json
import traceback

from .. import SteamWebBase, SteamIdParser


# https://developer.valvesoftware.com/wiki/Steam_Web_API/IEconService
class ETradeOfferState:
    Invalid = 1  # Invalid
    Active = 2  # This trade offer has been sent, neither party has acted on it yet.
    Accepted = 3  # The trade offer was accepted by the recipient and items were exchanged.
    Countered = 4  # The recipient made a counter offer
    Expired = 5  # The trade offer was not accepted before the expiration date
    Canceled = 6  # The sender cancelled the offer
    Declined = 7  # The recipient declined the offer

    # 	Some of the items in the offer are no longer available (indicated by the missing flag in the output)
    InvalidItems = 8
    # The offer hasn't been sent yet and is awaiting email/mobile confirmation. The offer is only visible to the sender.
    CreatedNeedsConfirmation = 9
    # Either party canceled the offer via email/mobile. The offer is visible to both parties,
    # even if the sender canceled it before it was sent.
    CanceledBySecondFactor = 10
    # The trade has been placed on hold. The items involved in the trade have all been removed from both parties'
    # inventories and will be automatically delivered in the future.
    InEscrow = 11


class ETradeOfferConfirmationMethod:
    Invalid = 0  # Invalid
    Email = 1  # An email was sent with details on how to confirm the trade offer
    MobileApp = 2  # The trade offer may be confirmed via the mobile app


class SteamTrade(SteamWebBase):
    ETradeOfferState = ETradeOfferState
    ETradeOfferConfirmationMethod = ETradeOfferConfirmationMethod

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = kwargs.get('api_key')

    @classmethod
    def is_valid_trade_url(cls, trade_url):
        regex = re.compile(r'^https?://steamcommunity\.com/tradeoffer/new/\?partner=(\d+)&token=([a-zA-Z0-9_-]+)$')
        return True if regex.match(trade_url) is not None else False

    @classmethod
    def get_parse_trade_url(cls, trade_url):
        regex = re.compile(r'^https?://steamcommunity\.com/tradeoffer/new/\?partner=(\d+)&token=([a-zA-Z0-9_-]+)$')
        match = regex.match(trade_url)
        if match:
            return None

        return {
            'token': match.group(1),
            'partner': match.group(2),
        }

    async def check_user_trade_url(self, trade_url):
        logging.debug('start check_user_trade_url, for: {}'.format(trade_url))

        trade_data = self.get_parse_trade_url(trade_url)
        if not trade_data:
            return {
                'is_valid': False,
                'message': 'Invalid trade url',
            }

        partner = trade_data['partner']
        token = trade_data['token']

        logging.debug('post check_user_trade_url, parsed: {}, {}'.format(token, partner))
        try:
            response = await self.session.send_session(
                url='https://steamcommunity.com/tradeoffer/new/?partner={}&token={}'.format(
                    partner,
                    token,
                ),
                is_post=False,
                timeout=10,
            )
        except Exception as e:
            logging.warning('expecion on checking trade url: {}, {}'.format(
                e,
                traceback.format_exc(),
            ))
            return {
                'is_valid': False,
                'message': 'Steam is down',
            }

        message = 'OK'
        if '<div id="error_msg">' in response:
            match = re.search(r'<div id="error_msg">([^<]+)</div>', response, re.MULTILINE | re.DOTALL)
            if match:
                message = match.group(1)
                message = str(message).strip()
            else:
                message = 'Steam is down'
                logging.warning('invalid message?: {}'.format(response))

            return {
                'is_valid': False,
                'message': message,
            }

        days_my_escrow = 0
        days_their_escrow = 0
        match = re.search(r'g_daysMyEscrow\s+=\s+(\d+);', response)
        if match:
            days_my_escrow = int(match.group(1))

        match = re.search(r'g_daysTheirEscrow\s+=\s+(\d+);', response)
        if match:
            days_their_escrow = int(match.group(1))

        is_full_valid = True if 'Make Offer' in response else False
        if not is_full_valid:
            logging.warning('invalid trade?: {}'.format(response))

        # we can't trade with user who have hold
        if days_their_escrow != 0:
            is_full_valid = False
            message = 'You don\'t have Steam Guard Mobile Authenticator.'

        return {
            'is_valid': is_full_valid,
            'message': message,
            'days_my_escrow': days_my_escrow,
            'days_their_escrow': days_their_escrow,
        }

    async def get_trade_url(self, timeout=None):
        referer = 'https://steamcommunity.com/profiles/{}/tradeoffers/privacy'.format(self.steam_id)
        raw_html = await self.session.send_session(
            url=referer,
            is_post=False,
            timeout=timeout,
        )

        regex = re.search(r'<input.*?id="trade_offer_access_url".*?value="(.*?)"', raw_html)
        if regex is None:
            url = 'https://steamcommunity.com/profiles/{}/tradeoffers/newtradeurl'.format(self.steam_id)
            new_token = await self.session.send_session(
                url=url,
                data={
                    'sessionid': self.session_id,
                },
                is_post=True,
                is_json=True,
                is_ajax=True,
                referer=referer,
                timeout=timeout,
            )

            return 'https://steamcommunity.com/tradeoffer/new/?partner={}&token={}'.format(
                self.steam_id.as_account(),
                new_token
            )

        # steam://url/NewTradeOffer/accountip&token=hash
        return regex.group(1)

    async def trade_send(self, **kwargs):
        logging.info('Send trade: {}'.format(kwargs))

        trade_hash_url = kwargs.get('trade_hash_url')
        items = kwargs.get('items', [
            [],
            [],
        ])
        msg = kwargs.get('msg', '')
        partner_sid = None

        if not items or len(items) != 2 or not isinstance(items[0], (list, tuple)) or not isinstance(items[1], (list, tuple)):
            raise AssertionError('Invalid items')

        if not trade_hash_url:
            partner_sid = SteamIdParser(kwargs.get('partner_sid64'))
            url_referer = 'https://steamcommunity.com/tradeoffer/new/?partner={account_id}'.format(
                account_id=partner_sid.as_account()
            )
        else:
            if not self.is_valid_trade_url(trade_hash_url):
                raise AssertionError('Invalid trade url')
            url_referer = trade_hash_url

        trade_json = {
            "newversion": True,
            "version": 2,
            "me": {
                "assets": items[0],  # {"appid": 440, "contextid": "2", "amount": 1, "assetid": "554608330"}
                "currency": [],
                "ready": False
            },
            "them": {
                "assets": items[1],
                "currency": [],
                "ready": False
            }
        }

        data = {
            'serverid': 1,
            'tradeoffermessage': msg,
            'json_tradeoffer': json.dumps(trade_json, separators=(',', ':')),
            'sessionid': self.session_id,
            'trade_offer_create_params': '{}',
        }
        if trade_hash_url:
            trade_data = self.get_parse_trade_url(trade_hash_url)
            if not trade_data:
                raise AssertionError('Invalid trade url')

            data.update({
                'trade_offer_create_params': json.dumps({
                    'trade_offer_access_token': trade_data['token']
                }, separators=(',', ':')),
                'partner': SteamIdParser(trade_data['partner']).as_64(),
            })
        else:
            data.update({
                'partner': partner_sid.as_64(),
            })

        logging.info('Send trade data: {}'.format(data))
        response = await self.session.send_session(
            url='https://steamcommunity.com/tradeoffer/new/send',
            data=data,
            is_post=True,
            is_json=True,
            referer=url_referer,
            timeout=kwargs.get('timeout', None),
        )
        logging.info('Send trade response: {}'.format(response))
        return response

    async def trade_accept(self, trade_id, partner_sid64, timeout=None):
        partner_sid = SteamIdParser(partner_sid64)
        data = await self.session.send_session(
            url='https://steamcommunity.com/tradeoffer/{}/accept'.format(trade_id),
            data={
                'sessionid': self.session_id,
                'serverid': '1',
                'tradeofferid': trade_id,
                'partner': partner_sid.as_64(),
                'captcha': '',
            },
            is_post=True,
            is_json=True,
            timeout=timeout,
            referer='https://steamcommunity.com/tradeoffer/{}/'.format(trade_id)
        )
        # {'needs_mobile_confirmation': True, 'needs_email_confirmation': True, 'email_domain': '', 'tradeid': None}
        return data

    async def trade_cancel(self, trade_id, is_api=True, timeout=None):
        """
        When my offer
        :param trade_id:
        :param is_api:
        :return:
        """
        if is_api:
            return await self._api_trade_cancel(trade_id, timeout=timeout)
        return await self._steam_trade_cancel(trade_id, timeout=timeout)

    async def trade_decline(self, trade_id, is_api=True, timeout=None):
        """
        When their offer
        :param trade_id:
        :param is_api:
        :return:
        """
        if is_api:
            return await self._api_trade_decline(trade_id, timeout=timeout)
        return await self._steam_trade_decline(trade_id, timeout=timeout)

    async def _steam_trade_cancel(self, trade_id, timeout=None):
        url = 'https://steamcommunity.com/tradeoffer/{}/cancel'.format(trade_id),
        referer = 'http://steamcommunity.com/profiles/{}/tradeoffers/sent'.format(self.steam_id)

        data = await self.session.send_session(
            url=url,
            data={
                'sessionid': self.session_id,
            },
            is_post=True,
            is_json=True,
            timeout=timeout,
            referer=referer
        )
        return data

    async def _steam_trade_decline(self, trade_id, timeout=None):
        url = 'https://steamcommunity.com/tradeoffer/{}/decline'.format(trade_id)
        referer = 'http://steamcommunity.com/profiles/{}/tradeoffers/'.format(self.steam_id)

        data = await self.session.send_session(
            url=url,
            data={
                'sessionid': self.session_id,
            },
            is_post=True,
            is_json=True,
            timeout=timeout,
            referer=referer
        )
        return data

    async def _api_trade_cancel(self, trade_id, timeout=None):
        context = {
            'key': self.api_key,
            'tradeofferid': trade_id,
        }

        return await self.session.send_request(
            url='https://api.steampowered.com/IEconService/CancelTradeOffer/v1/',
            is_post=True,
            is_json=True,
            data=context,
            timeout=timeout,
        )

    async def _api_trade_decline(self, trade_id, timeout=None):
        context = {
            'key': self.api_key,
            'tradeofferid': trade_id,
        }

        return await self.session.send_request(
            url='https://api.steampowered.com/IEconService/DeclineTradeOffer/v1/',
            is_post=True,
            is_json=True,
            data=context,
            timeout=timeout,
        )

    async def get_trade_offers(self, get_sent_offers=False, get_received_offers=True, get_history_only=False, timedelta_cutoff=3600, timeout=None):
        context = {
            'key': self.api_key,
            'get_sent_offers': 1 if get_sent_offers else 0,
            'get_received_offers': 1 if get_received_offers else 0,
            'get_descriptions': 1,
            'language': 'en',
            'active_only': int(not get_history_only),
            'historical_only': int(get_history_only),
            'time_historical_cutoff': int(time.time()) - timedelta_cutoff,  # data ponizej ktorej nie ma brac tradów -1h
        }

        return await self.session.send_request(
            url='https://api.steampowered.com/IEconService/GetTradeOffers/v1/',
            is_post=False,
            is_json=True,
            data=context,
            timeout=timeout,
        )

    async def get_trade_offer(self, trade_id, timeout=None):
        context = {
            'key': self.api_key,
            'tradeofferid': trade_id,
            'language': 'en',
        }

        return await self.session.send_request(
            url='https://api.steampowered.com/IEconService/GetTradeOffer/v1/',
            is_post=False,
            is_json=True,
            data=context,
            timeout=timeout,
        )

    async def get_backpack(self, app_id, context_id=2, group_by_market_name=True, timeout=None):
        response = await self.session.send_request(
            url='http://steamcommunity.com/profiles/{sid64}/inventory/json/{app_id}/{context_id}'.format(
                sid64=self.steam_id.as_64(),
                app_id=app_id,
                context_id=context_id,
            ),
            is_post=False,
            is_json=True,
            timeout=timeout,
        )

        if not group_by_market_name:
            return response

        if not response.get('rgInventory', {}):
            return {}, {}

        items = dict()
        descriptions = dict()
        for item in response.get('rgInventory', {}).values():
            key = '{}_{}'.format(
                item.get('classid'),
                item.get('instanceid'),
            )
            desc = response.get('rgDescriptions', {}).get(key, {})
            item_key = desc.get('market_hash_name')
            item_asset_id = int(item.get('id'))

            descriptions.setdefault(item_key, {
                'icon_url': desc.get('icon_url'),
                'icon_url_large': desc.get('icon_url_large'),
                'market_hash_name': desc['market_hash_name'],
            })

            if not desc.get('tradable'):
                continue
            items.setdefault(item_key, list()).append(item_asset_id)

        return items, descriptions
