from typing import Optional, Union
from datetime import datetime
from functools import cached_property

from ntlm.structures.av_pair import AVPairSequence, AvId, AvFlags, SingleHostData, EOLAVPair


class NTLMTargetInformation:
    def __init__(self, av_pairs: AVPairSequence):
        self._av_pairs: AVPairSequence = av_pairs

    def _get_property_value(self, av_id: AvId) -> Optional[Union[str, datetime, AvFlags, bytes, SingleHostData]]:
        av_pair: Optional[None] = next(
            (
                av_pair
                for av_pair in self._av_pairs
                if av_pair.AV_ID is av_id
            ),
            None
        )

        return av_pair.get_value() if av_pair is not None else None

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
