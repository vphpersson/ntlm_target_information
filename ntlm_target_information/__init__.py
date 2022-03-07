from typing import Optional
from logging import getLogger
from datetime import datetime
from functools import cached_property
from enum import Enum
from urllib.parse import urlparse
from ssl import OP_NO_TLSv1

from httpx import AsyncClient, create_ssl_context
from ldap3 import Connection as Ldap3Connection, Server as Ldap3Server, NTLM as Ldap3NTLM
from ntlm.structures.av_pairs import AvId
from ntlm.structures.av_pair_sequence import AVPairSequence
from ntlm.structures.av_pairs.eol import EOLAVPair
from ntlm.structures.single_host_data import SingleHostData
from ntlm.structures.av_pairs.flags import AvFlags

from ntlm_target_information.extraction.http import retrieve_http_ntlm_challenge
from ntlm_target_information.extraction.ldap import retrieve_ad_ldap_ntlm_challenge

LOG = getLogger(__name__)


class NTLMTargetInformation:
    def __init__(self, av_pairs: AVPairSequence):
        self._av_pairs: AVPairSequence = av_pairs

    def _get_property_value(self, av_id: AvId) -> Optional[str | datetime | AvFlags | bytes | SingleHostData]:
        try:
            return next(av_pair for av_pair in self._av_pairs if av_pair.AV_ID is av_id).get_value()
        except StopIteration:
            return None

    @cached_property
    def nb_domain_name(self) -> Optional[str]:
        return self._get_property_value(av_id=AvId.MsvAvNbDomainName)

    @cached_property
    def dns_computer_name(self) -> Optional[str]:
        return self._get_property_value(av_id=AvId.MsvAvDnsComputerName)

    @cached_property
    def dns_domain_name(self) -> Optional[str]:
        return self._get_property_value(av_id=AvId.MsvAvDnsDomainName)

    @cached_property
    def dns_tree_name(self) -> Optional[str]:
        return self._get_property_value(av_id=AvId.MsvAvDnsTreeName)

    @cached_property
    def timestamp(self) -> Optional[datetime]:
        return self._get_property_value(av_id=AvId.MsvAvTimestamp)

    @cached_property
    def flags(self) -> Optional[AvFlags]:
        return self._get_property_value(av_id=AvId.MsvAvFlags)

    @cached_property
    def channel_bindings(self) -> Optional[bytes]:
        return self._get_property_value(av_id=AvId.MsvChannelBindings)

    @cached_property
    def single_host_data(self) -> Optional[SingleHostData]:
        return self._get_property_value(av_id=AvId.MsvAvSingleHost)

    def __str__(self) -> str:
        return '\n'.join(sorted([
            f'{av_pair.LABEL}: {av_pair.get_value()}'
            for av_pair in self._av_pairs
            if not isinstance(av_pair, EOLAVPair)
        ]))


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
        ssl_context = create_ssl_context(verify=False)
        ssl_context.options ^= OP_NO_TLSv1
        async with AsyncClient(timeout=timeout, verify=ssl_context) as http_client:
            av_pairs = (await retrieve_http_ntlm_challenge(http_client=http_client, url=url)).target_info
    elif scheme in {SupportedScheme.LDAP, SupportedScheme.LDAPS}:
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
