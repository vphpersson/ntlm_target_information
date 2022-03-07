from typing import Any, Optional
from argparse import ArgumentParser, Namespace, Action
from urllib.parse import urlparse

from ntlm_target_information import SupportedScheme

from typed_argument_parser import TypedArgumentParser


class NTLMTargetInformationArgumentParser(TypedArgumentParser):

    class Namespace:
        url: str
        timeout: int

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(
                dict(
                    description='Output metadata about a server contained in an NTLM challenge message yielded from a specified endpoint.',
                ) | kwargs
            )
        )

        self.add_argument(
            'url',
            help='The URL of an endpoint that supports NTLM authentication, whose server to obtain information about.',
            type=str,
            action=self._ParseURLAction
        )

        self.add_argument(
            '-w', '--timeout',
            help='The number of seconds to wait before timing out when trying to connect to the endpoint.',
            type=int,
            default=5
        )

    class _ParseURLAction(Action):

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
