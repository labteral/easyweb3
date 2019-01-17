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


class EasyWeb3:
    def __init__(self,
                 filename=None,
                 password='',
                 http_provider=None,
                 alastria_node=None):
        logging.getLogger().setLevel(logging.INFO)
        logging.basicConfig(
            format='%(asctime)-15s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S')

        self.alastria_nodes = None
        self.w3 = None
        self.account = None

        if http_provider != None:
            self.w3 = Web3(HTTPProvider(http_provider))

        elif alastria_node != None:
            self.set_w3_instance_alastria(alastria_node)

        else:
            self.w3 = Web3()

        self.eth = self.w3.eth

        if filename != None:
            self._set_account_from_keystore(filename, password)
            logging.info(f'account: {self.account.address}')

    def _set_account_from_keystore(self, filename, password):
        try:
            with open(filename, 'r') as keystore:
                private_key = self.eth.account.decrypt(
                    next(keystore), password)
                self.account = self.eth.account.privateKeyToAccount(
                    private_key)
        except FileNotFoundError:
            logging.exception("message")

    def set_w3_instance_alastria(self, node=None):
        if node == None:
            if self.alastria_nodes == None:
                try:
                    with open('alastria-nodes.json', 'r') as json_file:
                        self.alastria_nodes = json.load(json_file)['nodes']
                        self.alastria_node_index = 0
                        node = self.alastria_nodes[self.alastria_node_index]
                except FileNotFoundError:
                    pass
            else:
                self.alastria_node_index = (
                    self.alastria_node_index + 1) % len(self.alastria_nodes)
                node = self.alastria_nodes[self.alastria_node_index]
        try:
            # Web3 instance
            self.w3 = Web3(Web3.HTTPProvider(f'http://{node}:22000'))
            # PoA compatibility middleware
            self.w3.middleware_stack.inject(geth_poa_middleware, layer=0)
        except Exception:
            logging.exception("message")
            self.set_w3_instance_alastria()

    def read(self, contract, method, parameters=None):
        if parameters == None:
            parameters = []
        return getattr(contract.functions, method)(*parameters).call()

    def transact(self, contract, method, parameters=None, nonce=None):
        if nonce == None:
            nonce = self.eth.getTransactionCount(self.account.address,
                                                 'pending')

        # TODO gas estimation and gas price
        tx_dict = {
            'nonce': nonce,
            'from': self.account.address,
            'gas': int(2e6),
            'gasPrice': Web3.toWei(50, 'gwei')
        }

        if parameters == None:
            parameters = []

        if method == 'constructor':
            tx = contract.constructor(*parameters)
        else:
            tx = getattr(contract.functions, method)(*parameters)

        built_tx = tx.buildTransaction(tx_dict)
        signed_tx = self.account.signTransaction(built_tx)
        tx_hash = self.eth.sendRawTransaction(signed_tx.rawTransaction)

        receipt = None
        while not receipt:
            logging.info('Waiting for the tx to be included in a block...')
            receipt = self.eth.getTransactionReceipt(tx_hash)
            time.sleep(1)
        logging.info(
            f'Transaction included in the block #{receipt["blockNumber"]}')
        return receipt

    def write(self, contract, method, parameters, nonce=None):
        return self.transact(contract, method, parameters, nonce)

    def deploy(self, contract, parameters=None, nonce=None):
        return self.transact(contract, 'constructor', parameters, nonce)

    @staticmethod
    def keccak256(item):
        return Web3.sha3(text=str(item)).hex()[2:]

    @staticmethod
    def hash(item):
        return EasyWeb3.keccak256(item)

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

    @classmethod
    def recover_address(cls, text, signature):
        if not hasattr(cls, 'w3'):
            cls.w3 = Web3()
        prefixed_hash = defunct_hash_message(text=text)
        return cls.w3.eth.account.recoverHash(
            prefixed_hash, signature=signature)
