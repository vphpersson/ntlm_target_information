#!/usr/bin/env python3

from asyncio import run as asyncio_run
from typing import Type
from logging import WARNING

from terminal_utils.log_handlers import ColoredLogHandler
from string_utils_py import text_align_delimiter

from ntlm_target_information import LOG, ntlm_target_information
from ntlm_target_information.cli import NTLMTargetInformationArgumentParser


async def main():
    args: Type[NTLMTargetInformationArgumentParser.Namespace] = NTLMTargetInformationArgumentParser().parse_args()

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
