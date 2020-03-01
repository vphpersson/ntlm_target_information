from setuptools import setup, find_packages

setup(
    name='ntlm_target_information',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'ntlm @ https://github.com/vphpersson/ntlm/tarball/master',
        'aiohttp',
        'ldap3'
    ]
)
