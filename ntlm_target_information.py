#!/usr/bin/env python3

from argparse import ArgumentParser, Action, Namespace
from enum import Enum, auto
from asyncio import run as asyncio_run
from sys import stderr
from typing import Optional, Set, Any
from urllib.parse import urlparse, ParseResult

from aiohttp import ClientSession, ClientTimeout
from ldap3 import Connection as Ldap3Connection, Server as Ldap3Server, NTLM as Ldap3NTLM

from ntlm_target_information import NTLMTargetInformation
from ntlm_target_information.exceptions import ExtractionError
from ntlm_target_information.extraction.http import retrieve_http_ntlm_challenge
from ntlm_target_information.extraction.ldap import retrieve_ad_ldap_ntlm_challenge


class TargetInformationMode(Enum):
    HTTP = auto()
    LDAP = auto()


HTTP_SCHEMES: Set[str] = {'http', 'https'}
LDAP_SCHEMES: Set[str] = {'ldap', 'ldaps'}
SUPPORTED_SCHEMES: Set[str] = HTTP_SCHEMES | LDAP_SCHEMES


class ParseURLAction(Action):

    def __call__(
        self,
        parser: ArgumentParser,
        namespace: Namespace,
        url: Any,
        _: Optional[str] = None
    ) -> None:
        parsed_url: ParseResult = urlparse(url=url)

        scheme: str = parsed_url.scheme.lower()
        if scheme in {'http', 'https'}:
            setattr(namespace, 'mode', TargetInformationMode.HTTP)
        elif scheme in {'ldap', 'ldaps'}:
            setattr(namespace, 'mode', TargetInformationMode.LDAP)
        else:
            return parser.error(
                message=f'Unsupported scheme: "{scheme}". Supported schemes: {", ".join(sorted(SUPPORTED_SCHEMES))}.'
            )

        setattr(namespace, 'url', url)


def get_parser() -> ArgumentParser:
    """Initialize the argument parser."""

    parser = ArgumentParser()

    parser.add_argument(
        'url',
        help='The URL of an endpoint that supports NTLM authentication.',
        type=str,
        action=ParseURLAction
    )

    parser.add_argument(
        '-w', '--timeout',
        help='The number of seconds to wait before timing out.',
        type=int,
        default=5
    )

    return parser


async def ntlm_target_information(mode: TargetInformationMode, url: str, timeout: float = 5.0) -> NTLMTargetInformation:

    if mode is TargetInformationMode.HTTP:
        async with ClientSession(timeout=ClientTimeout(total=timeout)) as client_session:
            av_pairs = (await retrieve_http_ntlm_challenge(client_session=client_session, url=url)).target_info
    elif mode is TargetInformationMode.LDAP:
        av_pairs = retrieve_ad_ldap_ntlm_challenge(
            connection=Ldap3Connection(
                server=Ldap3Server(host=url),
                authentication=Ldap3NTLM,
                read_only=True,
                user='\\',
                password=' ',
            )
        ).target_info
    else:
        raise ValueError(f'Unsupported mode: {mode}')

    return NTLMTargetInformation(av_pairs=av_pairs)


async def main() -> NTLMTargetInformation:
    args: Namespace = get_parser().parse_args()
    return await ntlm_target_information(mode=args.mode, url=args.url, timeout=args.timeout)


if __name__ == '__main__':
    try:
        print(asyncio_run(main()))
    except ExtractionError as e:
        print(e, file=stderr)
        exit(1)


