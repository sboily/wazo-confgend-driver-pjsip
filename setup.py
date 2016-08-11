#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
from setuptools import find_packages


setup(
    name='xivo-confgend-driver-pjsip',
    version='0.1',
    description='XIVO Configuration Generator for PJSIP',
    author='Sylvain Boily',
    author_email='sboily@proformatique.com',
    url='http://www.xivo.io/',
    license='GPLv3',
    packages=find_packages(),
    entry_points={
        'xivo_confgend.asterisk.pjsip.conf': [
            'xivo = xivo_confgend_driver_pjsip.pjsip_conf:PJSipConfGenerator'
        ],
    },
)
