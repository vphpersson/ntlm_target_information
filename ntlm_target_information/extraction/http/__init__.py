from base64 import b64encode, b64decode
from re import compile as re_compile

from httpx import AsyncClient
from ntlm.messages.challenge import ChallengeMessage
from ntlm.messages.negotiate import NegotiateMessage
from ntlm import NTLMContext

from ntlm_target_information.extraction.http.errors import WWWAuthenticateNotInHeadersError, \
    NoNTLMAuthenticationTypeError

NTLM_PATTERN = re_compile(r'^NTLM (?P<ntlm_data>[^,]+).*$')
WWW_AUTHENTICATE_FIELD_NAME = 'WWW-Authenticate'


async def retrieve_http_ntlm_challenge(http_client: AsyncClient, url: str) -> ChallengeMessage:

    # Empty authentication values are provided, as we are only interested in the `Challenge` message, and won't be
    # sending an `Authenticate` message.
    negotiate_message: NegotiateMessage = next(NTLMContext(username='', authentication_secret=b''))

    request_options = dict(
        url=url,
        headers={'Authorization': f'NTLM {b64encode(s=bytes(negotiate_message)).decode()}'},
    )
    response = await http_client.get(**request_options)

    try:
        return ChallengeMessage.from_bytes(
            buffer=b64decode(
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
