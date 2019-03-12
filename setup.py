#!/usr/bin/env python

from setuptools import setup

setup(
    name='keepassxc_browser',
    version='0.1.0',
    packages=['keepassxc_http',],
    install_requires=[
        'pysodium',
    ],
    description='Access the KeePassXC Browser API from Python',
    url='https://github.com/hrehfeld/python-keepassxc-browser',
    author='hrehfeld',
    license='AGPL-3.0',
)
