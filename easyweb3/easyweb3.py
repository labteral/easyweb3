#!/usr/bin/env python
# -*- coding: utf-8 -*-

from web3 import (
    Web3,
    middleware,
    exceptions,
)
from eth_account.messages import defunct_hash_message
import json
import time
import logging
from hexbytes import HexBytes
from easysolc import Solc
from math import ceil
from typing import Dict, List


class EasyWeb3:

    DEFAULT_GAS = int(4e6)
    WAIT_LOOP_SECONDS = 0.1
    WAIT_LOG_LOOP_SECONDS = 10
    DEFAULT_CONNECTION_TIMEOUT = 10

    @classmethod
    def init_class(cls):
        cls.web3 = Web3()

    @staticmethod
    def read(contract, method: str, parameters: List = None):
        if parameters is None:
            parameters = []
        return getattr(contract.functions, method)(*parameters).call()

    @staticmethod
    def get_rsv_from_signature(signature: str):
        if signature[0] == '0' and signature[1] == 'x':
            signature = signature[2:]
        r = signature[:64]
        s = signature[64:128]
        v = signature[128:]
        return r, s, int(v, 16)

    @classmethod
    def recover_address(cls, text: str, signature):
        if not hasattr(cls, 'eth'):
            cls.eth = Web3().eth
        prefixed_hash = defunct_hash_message(text=text)
        return cls.eth.account.recoverHash(prefixed_hash, signature=signature)

    @staticmethod
    def keccak256(item: str):
        return Web3.keccak(item).hex()[2:]

    @staticmethod
    def hash(item: str):
        return EasyWeb3.keccak256(item)

    def __init__(self,
                 account=None,
                 password: str = '',
                 http_provider: str = None,
                 http_providers=None,
                 http_providers_file: str = None,
                 proof_of_authority: bool = False,
                 timeout: int = None):
        self.proof_of_authority = proof_of_authority
        self.http_providers = None
        self.web3 = None
        self.account = None

        if timeout is None:
            self.timeout = EasyWeb3.DEFAULT_CONNECTION_TIMEOUT
        else:
            self.timeout = timeout

        if http_providers or http_providers_file:
            self.http_provider_index = -1
            if http_providers:
                if type(http_providers) == str:
                    http_providers = http_providers.replace(' ', '').split(',')
                elif type(http_providers) != list:
                    raise ValueError
                self.http_providers = http_providers
            elif http_providers_file:
                self.set_http_providers_from_file(http_providers_file)
            else:
                raise ValueError
            self.next_http_provider()
        elif http_provider:
            self.set_http_provider(http_provider)
        else:
            self.web3 = Web3()

        self.eth = self.web3.eth

        if account:
            if isinstance(account, dict):
                self.set_account_from_dict(account, password)
            else:
                self.set_account_from_file(account, password)
            logging.info(f'loaded account: {self.account.address}')

    def set_http_provider(self, http_provider: str):
        self.web3 = Web3(
            Web3.HTTPProvider(http_provider,
                              request_kwargs={'timeout': self.timeout}))
        if self.proof_of_authority:
            # PoA compatibility middleware
            self.web3.middleware_onion.inject(middleware.geth_poa_middleware,
                                              layer=0)
        logging.info(f'trying to connect to {http_provider}')

        # Test connection
        if not self.web3.isConnected():
            raise ConnectionError

    def set_account_from_dict(self, keystore: Dict, password: str):
        private_key = self.eth.account.decrypt(keystore, password)
        self.account = self.eth.account.privateKeyToAccount(private_key)

    def set_account_from_file(self, filename: str, password: str):
        try:
            with open(filename, 'r') as keystore_file:
                self.set_account_from_dict(json.load(keystore_file), password)
        except FileNotFoundError:
            logging.exception('')

    def set_http_providers_from_file(self, http_providers_file: str):
        if not http_providers_file:
            raise ValueError
        with open(http_providers_file, 'r') as json_file:
            self.http_providers = json.load(json_file)['nodes']

    def next_http_provider(self):
        self.http_provider_index = (self.http_provider_index + 1) % len(
            self.http_providers)
        http_provider = self.http_providers[self.http_provider_index]
        try:
            self.set_http_provider(http_provider)
        except Exception:
            self.next_http_provider()

    def get_tx(self,
               to,
               value=None,
               data=None,
               nonce=None,
               gas=None,
               gas_price=None,
               gas_price_multiplier: float = 1.0,
               pending: bool = True):
        if value is None:
            value = 0

        if nonce is None:
            nonce = self._get_nonce(pending)

        tx_dict = {
            'from': self.account.address,
            'to': to,
            'nonce': nonce,
            'value': value
        }

        if data is not None:
            tx_dict.update({'data': data})

        self._update_tx_dict_gas_params(tx_dict, gas, gas_price,
                                        gas_price_multiplier)
        return tx_dict

    def get_contract_tx(self,
                        contract,
                        method: str = 'constructor',
                        parameters: List = None,
                        nonce: int = None,
                        gas=None,
                        gas_price=None,
                        gas_price_multiplier: float = 1.0,
                        pending: bool = True):

        if parameters is None:
            parameters = []

        if method == 'constructor':
            invocation = contract.constructor(*parameters)
        else:
            invocation = getattr(contract.functions, method)(*parameters)

        if nonce is None:
            nonce = self._get_nonce(pending)

        tx_dict = invocation.buildTransaction({
            'from': self.account.address,
            'nonce': nonce,
            'gas': 0,
            'gasPrice': 0,
            'chainId': self.eth.chainId
        })
        self._update_tx_dict_gas_params(tx_dict, gas, gas_price,
                                        gas_price_multiplier)
        return tx_dict

    def sign_tx(self, tx):
        return self.account.signTransaction(tx)

    def transact(self,
                 tx=None,
                 signed_tx=None,
                 asynchronous: bool = False) -> Dict:
        if (tx is None and signed_tx is None) or \
           (tx is not None and signed_tx is not None):
            raise AttributeError

        if tx is not None:
            signed_tx = self.sign_tx(tx)

        if type(signed_tx) is not HexBytes:
            raw_tx = signed_tx.rawTransaction
        else:
            raw_tx = signed_tx
        tx_hash = self.eth.sendRawTransaction(raw_tx)

        if asynchronous:
            return {'transactionHash': tx_hash}

        receipt = None
        attempts = 0
        while not receipt:
            elapsed_seconds = attempts * EasyWeb3.WAIT_LOOP_SECONDS
            if elapsed_seconds % EasyWeb3.WAIT_LOG_LOOP_SECONDS == 0:
                logging.info(
                    f'waiting for the transaction to be included in a block '
                    f'({int(elapsed_seconds)} elapsed seconds)')

            try:
                receipt = self.eth.getTransactionReceipt(tx_hash)
                logging.info(f'transaction {tx_hash.hex()} included in the '
                             f'block #{receipt["blockNumber"]}')
                return receipt

            except exceptions.TransactionNotFound:
                attempts += 1
                time.sleep(EasyWeb3.WAIT_LOOP_SECONDS)

    def write(self, *args, **kwargs):
        return self._build_tx_and_transact(*args, **kwargs)

    def deploy(self, *args, **kwargs):
        kwargs['method'] = 'constructor'
        return self._build_tx_and_transact(*args, **kwargs)

    def get_contract(self,
                     contract_dict: Dict = None,
                     source: str = None,
                     contract_name: str = None,
                     address=None,
                     abi_file: str = None,
                     bytecode_file: str = None):
        contract = None
        if source and contract_name:
            if not hasattr(self, 'solc'):
                self.solc = Solc()
            contract_dict = self.solc.compile(source=source)[contract_name]
        if contract_dict:
            contract = self.eth.contract(abi=contract_dict['abi'],
                                         bytecode=contract_dict['bytecode'],
                                         address=address)
        elif abi_file:
            with open(abi_file, 'r') as abi_file:
                abi = json.loads(abi_file.read())
            if address:
                contract = self.eth.contract(abi=abi, address=address)
            elif bytecode_file:
                bytecode = None
                if bytecode_file:
                    with open(bytecode_file, 'r') as bytecode_file:
                        bytecode = bytecode_file.read()
                    contract = self.eth.contract(abi=abi, bytecode=bytecode)
                else:
                    raise ValueError(
                        "The bytecode or the address must be provided")
        return contract

    def sign(self, text: str):
        prefixed_hash = defunct_hash_message(text=text)
        signature = self.account.signHash(prefixed_hash)['signature'].hex()[2:]
        return signature

    def _get_nonce(self, pending: bool = True):
        if pending:
            return self.eth.getTransactionCount(self.account.address, 'pending')
        return self.eth.getTransactionCount(self.account.address)

    def _get_gas_price(self, gas_price, multiplier: float):
        if gas_price is None:
            gas_price = self.eth.gasPrice
        return ceil(multiplier * gas_price)

    def _get_gas_limit(self, tx_dict: Dict, gas=None):
        if gas is None:
            try:
                gas = self.eth.estimateGas(tx_dict)
            except Exception:
                gas = int(EasyWeb3.DEFAULT_GAS)
                logging.warn(f"failed to estimate gas, using default.")
        else:
            gas = int(gas)
        if gas >= self.eth.getBlock('latest').gasLimit or gas == 0:
            raise ValueError(f'gas limit not valid: {gas}')

        return gas

    def _update_tx_dict_gas_params(self, tx_dict: Dict, gas, gas_price,
                                   gas_price_multiplier: float):
        gas = self._get_gas_limit(tx_dict, gas=gas)
        logging.info(f"gas limit: {gas:,}")
        tx_dict.update({'gas': gas})

        gas_price = self._get_gas_price(gas_price, gas_price_multiplier)
        tx_dict.update({'gasPrice': gas_price})
        logging.info(
            f"network gas price: {self.web3.fromWei(self.eth.gasPrice, 'gwei')}"
            f" Gwei; using {self.web3.fromWei(gas_price, 'gwei')}"
            f" Gwei (x{gas_price_multiplier})")

    def _build_tx_and_transact(self, *args, **kwargs):
        tx = self.get_contract_tx(*args, **kwargs)
        asynchronous = False
        if 'asynchronous' in kwargs:
            asynchronous = kwargs['asynchronous']
        return self.transact(tx=tx, asynchronous=asynchronous)


EasyWeb3.init_class()
