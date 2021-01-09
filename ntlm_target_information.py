#!/usr/bin/env python3

from argparse import ArgumentParser, Action, Namespace
from logging import WARNING
from asyncio import run as asyncio_run
from typing import Optional, Any
from urllib.parse import urlparse

from terminal_utils.log_handlers import ColoredLogHandler
from pyutils.my_string import text_align_delimiter

from ntlm_target_information import LOG, SupportedScheme, ntlm_target_information


class NTLMTargetInformationArgumentParser(ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.add_argument(
            'url',
            help='The URL of an endpoint that supports NTLM authentication.',
            type=str,
            action=self.ParseURLAction
        )

        self.add_argument(
            '-w', '--timeout',
            help='The number of seconds to wait before timing out.',
            type=int,
            default=5
        )

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


async def main():
    args = NTLMTargetInformationArgumentParser().parse_args()

    LOG.addHandler(hdlr=ColoredLogHandler())
    LOG.setLevel(level=WARNING)

    try:
        print(
            text_align_delimiter(
                text=str(await ntlm_target_information(url=args.url, timeout=args.timeout)),
                delimiter=': '
            )
        )
    except:
        LOG.exception('Unexpected error.')

if __name__ == '__main__':
    asyncio_run(main())
