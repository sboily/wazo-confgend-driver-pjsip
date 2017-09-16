#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
from setuptools import find_packages


setup(
    name='wazo-confgend-driver-pjsip',
    version='0.0.2',
    description='Wazo Configuration Generator for PJSIP',
    author='Sylvain Boily',
    author_email='sboily@wazo.community',
    url='http://www.wazo.community/',
    license='GPLv3',
    packages=find_packages(),
    entry_points={
        'xivo_confgend.asterisk.pjsip.conf': [
            'wazo = wazo_confgend_driver_pjsip.pjsip_conf:PJSipConfGenerator'
        ],
    },
)
