from setuptools import setup, find_packages

setup(
    name='ntlm_target_information',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'ntlm @ git+ssh://git@github.com/vphpersson/ntlm.git#egg=ntlm',
        'pyutils @ git+ssh://git@github.com/vphpersson/pyutils.git#egg=pyutils',
        'terminal_utils @ git+ssh://git@github.com/vphpersson/terminal_utils.git#egg=terminal_utils',
        'httpx',
        'ldap3'
    ]
)
