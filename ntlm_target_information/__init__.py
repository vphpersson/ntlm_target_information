from base64 import b64encode, b64decode
from re import compile as re_compile
from contextlib import contextmanager

from aiohttp import ClientSession
from ldap3 import Connection as Ldap3Connection
from ldap3.utils.ntlm import NtlmClient

from ntlm.messages.challenge import ChallengeMessage
from ntlm.messages.negotiate import NegotiateMessage

NTLM_PATTERN = re_compile('^NTLM (?P<ntlm_data>[^,]+).*$')


# TODO: Make a custom exception for the case when the regex search fails.
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
        return ChallengeMessage.from_bytes(
            data=b64decode(
                s=NTLM_PATTERN.search(response.headers.get('WWW-Authenticate')).groupdict()['ntlm_data'].encode()
            )
        )


def retrieve_ad_ldap_ntlm_challenge(ldap_connection: Ldap3Connection) -> ChallengeMessage:
    """
    Extract the NTLM challenge message from NTLM authentication procedure over LDAP.

    :param ldap_connection: An unbound LDAP connection.
    :return: An NTLM challenge message resulting from an attempt to bind.
    """
    # Intercept the parsing of the LDAP server’s NTLM `CHALLENGE_MESSAGE` and extract the domain name from the
    # `DnsDomainName` value (FQDN of the domain) of the `TargetInfo` field.

    challenge_message = None

    def parse_challenge_message_wrapper(self, data: bytes) -> None:
        nonlocal challenge_message
        challenge_message = ChallengeMessage.from_bytes(data=data)

    @contextmanager
    def substitute_parse_challenge_message():
        parse_challenge_message_backup = NtlmClient.parse_challenge_message
        NtlmClient.parse_challenge_message = parse_challenge_message_wrapper
        yield
        NtlmClient.parse_challenge_message = parse_challenge_message_backup

    with substitute_parse_challenge_message():
        ldap_connection.bind()
        return challenge_message

# TODO: I should add something that returns either the AV pairs, or probably better a "target information" dataclass.