#!/usr/bin/env python
# -*- coding: utf-8 -*-

from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_account.messages import defunct_hash_message
import json
import time
import logging
from hexbytes import HexBytes
from easysolc import Solc
import signal


class EasyWeb3:
    def __init__(self,
                 filename=None,
                 password='',
                 http_provider=None,
                 http_providers=None,
                 http_providers_file=None,
                 proof_of_authority=False):
        self.proof_of_authority = proof_of_authority
        self.http_providers = None
        self.w3 = None
        self.account = None

        if http_provider:
            self._set_http_provider(http_provider)
        elif http_providers or http_providers_file:
            self.http_provider_index = -1
            if http_providers:
                if type(http_providers) == str:
                    http_providers = http_providers.replace(' ','').split(',')
                elif type(http_providers) != list:
                    raise ValueError
                self.http_providers = http_providers
            elif http_providers_file:
                self._set_http_providers_from_file(http_providers_file)
            else:
                raise ValueError
            self._set_next_http_provider()
        else:
            self.w3 = Web3()

        self.solc = None

        if filename:
            self._set_account_from_keystore(filename, password)
            logging.info(f'account: {self.account.address}')

    def _set_http_provider(self, http_provider):
        self.w3 = Web3(HTTPProvider(http_provider))
        self.eth = self.w3.eth
        if self.proof_of_authority:
            # PoA compatibility middleware
            self.w3.middleware_stack.inject(geth_poa_middleware, layer=0)
        logging.info(f'Trying to connect to {http_provider}')

        # Test connection
        try:
            signal.signal(signal.SIGALRM, lambda: TimeoutError())
            signal.alarm(2)
            if not self.w3.isConnected():
                raise ConnectionError
        finally:
            signal.alarm(0)

    def _set_account_from_keystore(self, filename, password):
        try:
            with open(filename, 'r') as keystore:
                private_key = self.eth.account.decrypt(
                    next(keystore), password)
                self.account = self.eth.account.privateKeyToAccount(
                    private_key)
        except FileNotFoundError:
            logging.exception('')

    def _set_http_providers_from_file(self, http_providers_file):
        if not http_providers_file:
            raise ValueError
        with open(http_providers_file, 'r') as json_file:
            self.http_providers = json.load(json_file)['nodes']

    def _set_next_http_provider(self):
        self.http_provider_index = (self.http_provider_index + 1) % len(
            self.http_providers)
        http_provider = self.http_providers[self.http_provider_index]
        try:
            self._set_http_provider(http_provider)
        except Exception:
            self._set_next_http_provider()

    def read(self, contract, method, parameters=None):
        if parameters == None:
            parameters = []
        return getattr(contract.functions, method)(*parameters).call()

    def get_signed_tx(self,
                      contract,
                      method,
                      parameters=None,
                      nonce=None,
                      gas=None,
                      gas_price=None):
        if nonce == None:
            nonce = self.eth.getTransactionCount(self.account.address,
                                                 'pending')
        if parameters == None:
            parameters = []

        if method == 'constructor':
            function_invocation = contract.constructor(*parameters)
        else:
            function_invocation = getattr(contract.functions,
                                          method)(*parameters)

        if gas == None:
            try:
                gas = function_invocation.estimateGas()
            except Exception:
                gas = int(4e6)
                logging.warn(f'Could not estimate gas for {method}()')

        if gas_price == None:
            gas_price = self.eth.gasPrice

        logging.info(f'Signing tx with gas={gas} and gasPrice={gas_price}')

        tx_dict = {
            'nonce': nonce,
            'from': self.account.address,
            'gas': gas,
            'gasPrice': gas_price
        }

        built_tx = function_invocation.buildTransaction(tx_dict)
        signed_tx = self.account.signTransaction(built_tx)
        return signed_tx

    def transact(self,
                 contract=None,
                 method=None,
                 parameters=None,
                 nonce=None,
                 signed_tx=None):
        if not signed_tx and (not contract or not method):
            raise ValueError

        if not signed_tx:
            signed_tx = self.get_signed_tx(contract, method, parameters, nonce)
        tx_hash = self.eth.sendRawTransaction(signed_tx.rawTransaction)

        attempts = 0
        receipt = None
        while not receipt:
            logging.info(
                f'Waiting for the tx to be included in a block ({attempts})')
            receipt = self.eth.getTransactionReceipt(tx_hash)
            attempts += 1
            time.sleep(1)
        logging.info(
            f'Transaction included in block #{receipt["blockNumber"]}')
        return receipt

    def write(self, contract, method, parameters, nonce=None):
        return self.transact(contract, method, parameters, nonce)

    def deploy(self, contract, parameters=None, nonce=None):
        return self.transact(contract, 'constructor', parameters, nonce)

    def get_contract(self,
                     contract_dict=None,
                     source=None,
                     contract_name=None,
                     address=None,
                     abi_file=None,
                     bytecode_file=None):
        contract = None
        if source and contract_name:
            if not self.solc:
                self.solc = Solc()
            contract_dict = self.solc.compile(source=source)[contract_name]
        if contract_dict:
            contract = self.eth.contract(
                abi=contract_dict['abi'], bytecode=contract_dict['bytecode'], address=address)            
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
                    raise ValueError("The bytecode or the address must be provided")
        return contract

    def get_rsv_from_signature(self, signature):
        if signature[0] == '0' and signature[1] == 'x':
            signature = signature[2:]
        r = signature[:64]
        s = signature[64:128]
        v = signature[128:]
        return r, s, int(v, 16)

    def sign(self, text):
        prefixed_hash = defunct_hash_message(text=text)
        signature = self.account.signHash(prefixed_hash)['signature'].hex()[2:]
        return signature

    def recover_address(self, text, signature):
        prefixed_hash = defunct_hash_message(text=text)
        return self.eth.account.recoverHash(
            prefixed_hash, signature=signature)

    @staticmethod
    def keccak256(item):
        return Web3.sha3(text=str(item)).hex()[2:]

    @staticmethod
    def hash(item):
        return EasyWeb3.keccak256(item)