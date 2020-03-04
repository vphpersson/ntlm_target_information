#!/usr/bin/env python3

from argparse import ArgumentParser, Action, Namespace
from enum import Enum
from asyncio import run as asyncio_run
from sys import stderr
from typing import Optional, Any
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout
from ldap3 import Connection as Ldap3Connection, Server as Ldap3Server, NTLM as Ldap3NTLM

from ntlm_target_information import NTLMTargetInformation
from ntlm_target_information.exceptions import ExtractionError
from ntlm_target_information.extraction.http import retrieve_http_ntlm_challenge
from ntlm_target_information.extraction.ldap import retrieve_ad_ldap_ntlm_challenge


class SupportedScheme(Enum):
    HTTP = 'http'
    HTTPS = 'https'
    LDAP = 'ldap'
    LDAPS = 'ldaps'


async def ntlm_target_information(url: str, timeout: float = 5.0) -> NTLMTargetInformation:
    """
    Retrieve information about a target from metadata in an NTLM challenge message.

    :param url: The URL of a target endpoint that supports NTLM authentication.
    :param timeout: The number of seconds to wait before timing out a network request.
    :return: Information about the target contained in an NTLM challenge message.
    """

    scheme: SupportedScheme = SupportedScheme(urlparse(url=url).scheme.lower())

    if scheme in {SupportedScheme.HTTP, SupportedScheme.HTTPS}:
        async with ClientSession(timeout=ClientTimeout(total=timeout)) as client_session:
            av_pairs = (await retrieve_http_ntlm_challenge(client_session=client_session, url=url)).target_info
    elif scheme in {SupportedScheme.LDAP, SupportedScheme.LDAPS}:
        # TODO: Add timeout?
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
        raise ValueError(f'Unsupported scheme: {scheme}')

    return NTLMTargetInformation(av_pairs=av_pairs)


class ParseURLAction(Action):

    def __call__(
        self,
        parser: ArgumentParser,
        namespace: Namespace,
        url: Any,
        _: Optional[str] = None
    ) -> None:
        """
        Handle the parsing of the URL argument.

        :param parser: The argument parser on which the action is registered.
        :param namespace: The namespace that will contain the parsed arguments.
        :param url: The value of the URL argument passed by the user.
        :return: None
        """

        scheme: str = urlparse(url=url).scheme.lower()

        try:
            SupportedScheme(value=scheme)
        except ValueError:
            return parser.error(
                message=(
                    f'Unsupported scheme: "{scheme}". '
                    f'Supported schemes: {", ".join(sorted(mode.value for mode in SupportedScheme))}.'
                )
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


async def main() -> NTLMTargetInformation:
    args: Namespace = get_parser().parse_args()
    return await ntlm_target_information(url=args.url, timeout=args.timeout)


if __name__ == '__main__':
    try:
        print(asyncio_run(main()))
    except ExtractionError as e:
        print(e, file=stderr)
        exit(1)


