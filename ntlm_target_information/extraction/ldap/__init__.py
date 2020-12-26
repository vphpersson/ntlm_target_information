from contextlib import contextmanager

from ldap3 import Connection as Ldap3Connection
from ldap3.utils.ntlm import NtlmClient

from ntlm.messages.challenge import ChallengeMessage


def retrieve_ad_ldap_ntlm_challenge(connection: Ldap3Connection) -> ChallengeMessage:
    """
    Extract the NTLM challenge message from NTLM authentication procedure over LDAP.

    :param connection: An unbound LDAP connection.
    :return: An NTLM challenge message resulting from an attempt to bind.
    """
    # Intercept the parsing of the LDAP server’s NTLM `CHALLENGE_MESSAGE` and extract the domain name from the
    # `DnsDomainName` value (FQDN of the domain) of the `TargetInfo` field.

    challenge_message = None

    def parse_challenge_message_wrapper(self, data: bytes) -> None:
        nonlocal challenge_message
        challenge_message = ChallengeMessage.from_bytes(buffer=data)

    @contextmanager
    def substitute_parse_challenge_message():
        parse_challenge_message_backup = NtlmClient.parse_challenge_message
        NtlmClient.parse_challenge_message = parse_challenge_message_wrapper
        yield
        NtlmClient.parse_challenge_message = parse_challenge_message_backup

    with substitute_parse_challenge_message():
        try:
            connection.bind()
        except Exception:
            pass

        return challenge_message
