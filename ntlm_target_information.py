#!/usr/bin/env python3

from re import compile as re_compile
from argparse import ArgumentParser
from enum import Enum, auto
from asyncio import run as asyncio_run
from sys import stderr

from aiohttp import ClientSession, ClientTimeout
from ntlm.structures.av_pair import EOLAVPair

from ntlm_target_information import retrieve_http_ntlm_challenge


NTLM_PATTERN = re_compile('^NTLM (?P<ntlm_data>[^,]+).*$')


class TargetInformationMode(Enum):
    HTTP = auto()
    LDAP = auto()


def get_parser() -> ArgumentParser:
    """Initialize the argument parser."""

    parser = ArgumentParser()

    subparsers = parser.add_subparsers(help='The method with which to retrieve the target information.')

    http_owa_parser = subparsers.add_parser(
        name=TargetInformationMode.HTTP.name.lower()
    )
    http_owa_parser.set_defaults(mode=TargetInformationMode.HTTP)

    http_owa_parser.add_argument(
        'url',
        help='The URL of an HTTP endpoint that supports NTLM authentication.',
        type=str
    )

    http_owa_parser.add_argument(
        '-w', '--timeout',
        help='The number of seconds to wait before timing out.',
        type=int,
        default=5
    )

    ldap_ad_parser = subparsers.add_parser(
        name=TargetInformationMode.LDAP.name.lower()
        # parents=[LdapServerAddressParser()]
    )
    ldap_ad_parser.set_defaults(mode=TargetInformationMode.LDAP)

    return parser


async def ntlm_target_information():

    parser = get_parser()
    args = parser.parse_args()

    if getattr(args, 'mode', None) is None:
        return parser.error(message='No mode selected.')

    async with ClientSession(timeout=ClientTimeout(total=args.timeout)) as client_session:
        av_pairs = (await retrieve_http_ntlm_challenge(client_session=client_session, url=args.url)).target_info

    if av_pairs is None:
        print('No NTLM target information available.', file=stderr)
    else:
        print(
            '\n'.join(sorted([
                f'{av_pair.LABEL}: {av_pair.get_value()}'
                for av_pair in av_pairs
                if not isinstance(av_pair, EOLAVPair)
            ]))
        )


if __name__ == '__main__':
    asyncio_run(ntlm_target_information())



