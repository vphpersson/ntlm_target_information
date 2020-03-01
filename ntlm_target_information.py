#!/usr/bin/env python3

from re import compile as re_compile
from argparse import ArgumentParser
from enum import Enum, auto
from asyncio import run as asyncio_run

from aiohttp import ClientSession, ClientTimeout
from ntlm.structures.av_pair import EOLAVPair

from ntlm_target_information import retrieve_http_ntlm_challenge


NTLM_PATTERN = re_compile('^NTLM (?P<ntlm_data>[^,]+).*$')


class TargetInformationMode(Enum):
    HTTP_OWA = auto()
    LDAP_AD = auto()


def get_parser() -> ArgumentParser:
    """Initialize the argument parser."""

    parser = ArgumentParser()

    subparsers = parser.add_subparsers(help='The method with which to retrieve the target information.')

    http_owa_parser = subparsers.add_parser(
        name=TargetInformationMode.HTTP_OWA.name.lower()
    )
    http_owa_parser.set_defaults(which=TargetInformationMode.HTTP_OWA)

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
        name=TargetInformationMode.LDAP_AD.name.lower()
        # parents=[LdapServerAddressParser()]
    )
    ldap_ad_parser.set_defaults(which=TargetInformationMode.LDAP_AD)

    return parser


async def main():
    args = get_parser().parse_args()

    async with ClientSession(timeout=ClientTimeout(total=args.timeout)) as client_session:
        av_pairs = (await retrieve_http_ntlm_challenge(client_session=client_session, url=args.url)).target_info

    if av_pairs is None:
        # TODO: Use proper exception.
        raise ValueError('no av pairs')

    print(
        '\n'.join(sorted([
            f'{av_pair.LABEL}: {av_pair.get_value()}'
            for av_pair in av_pairs
            if not isinstance(av_pair, EOLAVPair)
        ]))
    )


if __name__ == '__main__':
    asyncio_run(main())



