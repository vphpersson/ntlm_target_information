from base64 import b64encode, b64decode
from re import compile as re_compile

from aiohttp import ClientSession
from ntlm.messages.challenge import ChallengeMessage
from ntlm.messages.negotiate import NegotiateMessage

from ntlm_target_information.extraction.http.exceptions import WWWAuthenticateNotInHeadersError, \
    NoNTLMAuthenticationTypeError

NTLM_PATTERN = re_compile(r'^NTLM (?P<ntlm_data>[^,]+).*$')
WWW_AUTHENTICATE_FIELD_NAME = 'WWW-Authenticate'


async def retrieve_http_ntlm_challenge(client_session: ClientSession, url: str) -> ChallengeMessage:

    negotiate_message = NegotiateMessage.make_ntlm_v2_negotiate()
    # TODO: I want this flag to be set by default in `NegotiateMessage.make_ntlm_v2_negotiate`, but I need to add the
    #   actual support for that.
    negotiate_message.negotiate_flags.negotiate_extended_sessionsecurity = True

    request_options = dict(
        url=url,
        method='GET',
        headers={'Authorization': f'NTLM {b64encode(s=bytes(negotiate_message)).decode()}'},
        verify_ssl=False
    )
    async with client_session.request(**request_options) as response:
        try:
            return ChallengeMessage.from_bytes(
                data=b64decode(
                    s=NTLM_PATTERN.search(
                        response.headers[WWW_AUTHENTICATE_FIELD_NAME]
                    ).groupdict()['ntlm_data'].encode()
                )
            )
        except KeyError as e:
            if e.args[0] != WWW_AUTHENTICATE_FIELD_NAME:
                raise e
            raise WWWAuthenticateNotInHeadersError(response=response)
        except AttributeError:
            raise NoNTLMAuthenticationTypeError(response=response)
