#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .easyweb3 import *
import logging

__version__ = '1.215.0'

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)-15s [%(levelname)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.info(f'EasyWeb3 v{__version__}')
