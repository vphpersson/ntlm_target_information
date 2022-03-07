from setuptools import setup, find_packages

setup(
    name='ntlm_target_information',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'ntlm @ git+https://github.com/vphpersson/ntlm.git#egg=ntlm',
        'string_utils_py @ git+https://github.com/vphpersson/string_utils_py.git#egg=string_utils_py',
        'terminal_utils @ git+https://github.com/vphpersson/terminal_utils.git#egg=terminal_utils',
        'typed_argument_parser @ git+https://github.com/vphpersson/typed_argument_parser.git#egg=typed_argument_parser',
        'httpx',
        'ldap3'
    ]
)
