#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .easyweb3 import EasyWeb3
import logging

__version__ = '0.1.7'

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)-15s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logging.info(f'EasyWeb3 v{__version__}')
