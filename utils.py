import asyncio
import json as js
import random
import time

import aiohttp
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from eth_utils import to_hex
from loguru import logger
from web3 import AsyncWeb3, Web3
from web3.contract import AsyncContract
from web3.eth import AsyncEth

from config import rpc, gwei, delay

address = '0xD4B812DD7134F632C947CA11a2Fb0f49082a2483'
aevo_address = '0xB528edBef013aff855ac3c50b381f253aF13b997'
abi = '[{"inputs":[{"internalType":"address","name":"token_","type":"address"},{"internalType":"bytes32","name":"merkleRoot_","type":"bytes32"},{"internalType":"uint256","name":"endTime_","type":"uint256"},{"internalType":"address","name":"beneficiary_","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"address","name":"target","type":"address"}],"name":"AddressEmptyCode","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"AddressInsufficientBalance","type":"error"},{"inputs":[],"name":"AlreadyClaimed","type":"error"},{"inputs":[],"name":"ClaimWindowFinished","type":"error"},{"inputs":[],"name":"EndTimeInPast","type":"error"},{"inputs":[],"name":"FailedInnerCall","type":"error"},{"inputs":[],"name":"InvalidProof","type":"error"},{"inputs":[],"name":"NoWithdrawDuringClaim","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"inputs":[{"internalType":"address","name":"token","type":"address"}],"name":"SafeERC20FailedOperation","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"index","type":"uint256"},{"indexed":false,"internalType":"address","name":"account","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Claimed","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"},{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"bytes32[]","name":"merkleProof","type":"bytes32[]"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"endTime","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"isClaimed","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"merkleRoot","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"token","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]'
token_abi = '[{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_symbol","type":"string"},{"internalType":"uint8","name":"_decimals","type":"uint8"},{"internalType":"address","name":"_beneficiary","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AccessControlBadConfirmation","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bytes32","name":"neededRole","type":"bytes32"}],"name":"AccessControlUnauthorizedAccount","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[],"name":"ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MINTER_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_recipient","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"callerConfirmation","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'
scan = 'https://etherscan.io/tx/'


class Account:
    def __init__(self, key, *, id: str = '1', address_to=None):
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(
            rpc), modules={'eth': (AsyncEth,)}, middlewares=[])
        self.account = self.w3.eth.account.from_key(key)
        self.address = self.account.address
        self.address_to = address_to
        self.acc_info = f'{id}) {self.address_to}'
        self.contract = self.get_contract(address=Web3.to_checksum_address(address), abi=abi)

    def get_contract(self, address, abi) -> AsyncContract:
        return self.w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)

    @staticmethod
    async def sleep_indicator(secs, info):
        logger.info(f'{info} - жду {secs} секунд')
        await asyncio.sleep(secs)

    async def check_status_tx(self, tx_hash):
        logger.info(f'{self.acc_info} - жду подтверждения транзакции...')
        start_time = int(time.time())
        while True:
            current_time = int(time.time())
            if current_time >= start_time + 100:
                logger.debug(
                    f'{self.acc_info} - транзакция не подтвердилась за 100 cекунд, начинаю повторную отправку...')
                return 0
            try:
                status = (await self.w3.eth.get_transaction_receipt(tx_hash))['status']
                if status == 1:
                    return status
                await asyncio.sleep(1)
            except Exception as error:
                await asyncio.sleep(1)

    async def sign_and_send(self, tx):
        try:
            sign = self.account.sign_transaction(tx)
            hash_ = await self.w3.eth.send_raw_transaction(sign.rawTransaction)
            status = await self.check_status_tx(hash_)
            return status, hash_
        except Exception as e:
            logger.error(f'{self.acc_info} - ошибка при отправке транзакции : \n{e}')
            return

    async def build_tx(self, func=None, value=0, args=None):
        w3 = self.w3
        try:
            nonce = await w3.eth.get_transaction_count(self.address)
            func_ = getattr(self.contract.functions, func)
            tx_dict = {
                'from': self.address,
                'nonce': nonce,
                'value': value,
                'maxFeePerGas': 0,
                'maxPriorityFeePerGas': 0
            }
            if args is None:
                tx = await func_().build_transaction(tx_dict)
            elif type(args) != list and type(args) != str:
                tx = await func_(*args).build_transaction(tx_dict)
            else:
                tx = await func_(args).build_transaction(tx_dict)
            gas = int(await self.w3.eth.gas_price * 1.1)
            tx['maxPriorityFeePerGas'] = gas
            tx['maxFeePerGas'] = gas
            tx['gas'] = await w3.eth.estimate_gas(tx)
            return tx
        except Exception as e:
            if '0x646cf558' in str(e):
                logger.error(f'{self.acc_info} - уже заклеймлено')
                return
            logger.error(f'{self.acc_info} - {e}')
            return False

    @staticmethod
    async def send_request(url, method, *, params=None, json=None, headers=None, proxy=None):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, headers=headers, params=params, json=json,
                                           proxy=proxy) as response:
                    if response.status in [200, 201]:
                        return js.loads(await response.text())
                    await asyncio.sleep(1)
                    logger.error(f'Ошибка при отправке запроса {url}: {await response.text()}')
                    return
        except Exception as e:
            logger.error(f'Ошибка - {e}...')
            return

    async def check_eligible(self):
        try:
            data = await self.send_request('https://api-ribbon.vercel.app/api/aevo/check-eligibility', 'GET', params={
                'address': self.address})
            if not data:
                return
            return data['airdrop']
        except Exception as e:
            logger.error(f'Ошибка - {e}...')
            return

    async def get_proof(self):
        try:
            if not await self.check_eligible():
                logger.error(f'{self.acc_info} - не элиджбл для клейма AEVO')
                return

            message = f"Claiming Aevo Airdrop {self.address}"
            sign = self.account.sign_message(encode_defunct(hexstr=to_hex(keccak(message.encode('utf-8')))))
            params = {
                'address': self.address,
                'message': message,
                'signature': to_hex(sign.signature),
            }
            data = await self.send_request('https://api-ribbon.vercel.app/api/aevo/airdrop-proof', 'POST',
                                           params=params)
            if not data:
                return
            data = data['data']['claim']
            return int(data['index']), int(data['amount'], 16), data['proof']
        except Exception as e:
            logger.error(f'Ошибка - {e}...')
            return

    async def check_gas(self):
        while True:
            try:
                gas = await self.w3.eth.gas_price
                gas_ = self.w3.from_wei(gas, 'gwei')
                logger.success(f'{self.acc_info} - gwei сейчас - {gas_}...')
                if gwei > gas_:
                    return True
                logger.error(f'{self.acc_info} gwei слишком большой, жду понижения...')
                await asyncio.sleep(30)
            except Exception as e:
                logger.error(f'{self.acc_info} - {e}')
                await asyncio.sleep(1)
                return await self.check_gas()

    async def get_balance(self, address_contract) -> int:
        contract = self.get_contract(address=Web3.to_checksum_address(address_contract), abi=token_abi)
        try:
            balance = await contract.functions.balanceOf(self.address).call()
            return balance
        except Exception as e:
            logger.error(f'{self.acc_info} - {e}')
            await asyncio.sleep(1)
            return await self.get_balance(address_contract)

    async def claim(self):
        data = await self.get_proof()
        if not data:
            return
        index, amount, proof = data
        await self.check_gas()
        tx = await self.build_tx('claim', args=(index, self.address, amount, proof))
        if not tx:
            return
        data = await self.sign_and_send(tx)
        if not data: return
        status, hash_ = data
        if status:
            logger.success(
                f'{self.acc_info} - успешно заклеймил {amount / 10 ** 18} AEVO\ntx: {scan}{to_hex(hash_)}')
            await self.sleep_indicator(random.uniform(*delay), f'{self.acc_info}:')
            return True
        else:
            logger.error(f'{self.acc_info} - транзакция не успешна...')
            return False

    async def transfer(self):
        if not self.address_to:
            logger.error(f'{self.acc_info} - не указан адрес для отправки')
            return

        balance = await self.get_balance(aevo_address)
        if balance == 0:
            logger.error(f'{self.acc_info} - нечего отправлять')
            return

        await self.check_gas()
        try:
            tx = {
                "from": self.address,
                "to": Web3.to_checksum_address(aevo_address),
                "maxFeePerGas": 0,
                "maxPriorityFeePerGas": 0,
                "nonce": await self.w3.eth.get_transaction_count(
                    self.address
                ),
                "chainId": 1,
                "data": self.get_contract(aevo_address, abi=token_abi).encodeABI('transfer',
                                                                                 [Web3.to_checksum_address(self.address_to),
                                                                                  balance])
            }
            gas = int(await self.w3.eth.gas_price * 1)
            tx['maxPriorityFeePerGas'] = gas
            tx['maxFeePerGas'] = gas
            tx['gas'] = await self.w3.eth.estimate_gas(tx)
            data = await self.sign_and_send(tx)
            if not data: return
            status, hash_ = data
            if status:
                logger.success(
                    f'{self.acc_info} - успешно отправил {balance / 10 ** 18} AEVO\ntx: {scan}{to_hex(hash_)}')
                await self.sleep_indicator(random.uniform(*delay), f'{self.acc_info}:')
                return True
            else:
                logger.error(f'{self.acc_info} - транзакция не успешна...')
                return False
        except Exception as e:
            logger.error(f'{self.acc_info} - {e}')
            return

