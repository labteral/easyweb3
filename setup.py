#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import find_packages
from setuptools import setup
import easyweb3

setup(name='easyweb3',
      version=easyweb3.__version__,
      description='Work easier with Web3 in Python',
      url='https://github.com/brunneis/easyweb3',
      author='Rodrigo Martínez',
      author_email='dev@brunneis.com',
      license='GNU General Public License v3.0',
      packages=find_packages(),
      zip_safe=False,
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: Implementation :: PyPy',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],
      python_requires=">=3.6",
      install_requires=['web3>=5.19.0, <6.0.0', 'easysolc'])

