from fields import Field, MetaField, IntField, StringField, ListField, LengthField


class IPv4AddressField(Field):
    def __init__(self, value: str, size: int, name: str) -> None:
        super().__init__(value, size, name)

    def to_bytes(self) -> bytes:
        octets = self.value.split('.')
        if len(octets) != 4:
            raise ValueError('Invalid IP address.')
        return b''.join([int(octet).to_bytes(1, 'big') for octet in octets[: self.size]])


class PathAttribute(ListField):
    def __init__(self, flags: int, type_code: int, name: str) -> None:
        """
        0... ....: Optional
        .0.. ....: Transitive
        ..0. ....: Partial
        ...0 ....: Extended Length
        .... 0000: Unused
        """
        self.flags = IntField(flags, 1, 'Flags')
        self.type_code = IntField(type_code, 1, 'Type Code')
        self.length = LengthField(None, 1, 'Length')
        if flags & 0b00010000 == 0b00010000:
            self.length = LengthField(None, 2, 'Length')

        fields = [
            self.flags,
            self.type_code,
            self.length,
        ]
        super().__init__(fields, name)

    def __len__(self):
        return self.length.derive() + self.flags.size + self.type_code.size + self.length.size


class Origin(PathAttribute):
    """
    Origin Codes:
        - IGP (0)
        - EGP (1)
        - INCOMPLETE (2)
    """

    def __init__(self, flags, origin) -> None:
        super().__init__(flags, 1, 'Path Attribute: Origin')
        self.origin = IntField(origin, 1, 'Origin')
        self.append(self.origin)
        self.length.dependencies = [self.origin]


class ASPath(PathAttribute):
    def __init__(self, flags: int, asn_size: int, asns: list[int]) -> None:
        super().__init__(flags, 2, 'Path Attribute: AS Path')
        self.segment_type = IntField(2, 1, 'Segment Type')
        self.segment_length = IntField(len(asns), 1, 'Segment Length')
        asns = [IntField(asn, asn_size, f'ASN {i}') for i, asn in enumerate(asns)]
        self.asns = ListField(asns, 'AS Path')
        self.append(self.segment_type)
        self.append(self.segment_length)
        self.append(self.asns)
        self.length.dependencies = [self.segment_type, self.segment_length, self.asns]


class NextHop(PathAttribute):
    def __init__(self, flags: int, next_hop: str) -> None:
        super().__init__(flags, 3, 'Path Attribute: Next Hop')
        self.next_hop = IPv4AddressField(next_hop, 4, 'Next Hop')
        self.append(self.next_hop)
        self.length.dependencies = [self.next_hop]


class MultiExitDisc(PathAttribute):
    def __init__(self, flags: int, med: int) -> None:
        super().__init__(flags, 4, 'Path Attribute: Multi Exit Disc')
        self.med = IntField(med, 4, 'MED')
        self.append(self.med)
        self.length.dependencies = [self.med]


class LocalPref(PathAttribute):
    def __init__(self, flags: int, local_pref: int) -> None:
        super().__init__(flags, 5, 'Path Attribute: Local Preference')
        self.local_pref = IntField(local_pref, 4, 'Local Preference')
        self.append(self.local_pref)
        self.length.dependencies = [self.local_pref]


class NetworkLayerReachabilityInformation(ListField):
    def __init__(self, address: str, prefix: int) -> None:
        self.prefix_length = IntField(prefix, 1, 'Prefix Length')
        self.address = IPv4AddressField(address, 3, 'Prefix')
        super().__init__([self.prefix_length, self.address], 'Network Layer Reachability Information')


class Capability(ListField):
    def __init__(self, type_code: int, name: str) -> None:
        self.type_code = IntField(type_code, 1, 'Type Code')
        self.length = LengthField([], 1, 'Length')
        super().__init__([self.type_code, self.length], name)


class MultiprotocolExtensions(Capability):  # 1
    """
    AFI:
        - IPv4 (1)
        - IPv6 (2)
        - L2VPN (25)
    SAFI:
        - Unicast (1)
        - Multicast (2)
        - MPLS (4)
        - EVPN (70)
    """

    def __init__(self, afi: int, safi: int) -> None:
        super().__init__(1, 'Capability: Multiprotocol Extensions')
        self.afi = IntField(afi, 2, 'AFI')
        self.reserved = IntField(0, 1, 'Reserved')
        self.safi = IntField(safi, 1, 'SAFI')
        self.append(self.afi)
        self.append(self.reserved)
        self.append(self.safi)
        self.length.dependencies.extend([self.afi, self.reserved, self.safi])


class RouteRefresh(Capability):  # 2
    def __init__(self) -> None:
        super().__init__(2, 'Capability: Route Refresh')


class BGPExtended(Capability):  # 6
    def __init__(self):
        super().__init__(6, 'Capability: BGP Extended')


class GracefulRestart(Capability):  # 64
    """
    0... .... .... .... = Restart State
    .0.. .... .... .... = Graceful Notification
    .... 0000 0000 0000 = Time
    """

    def __init__(self, restart_state: bool, graceful_notification: bool, time: int) -> None:
        super().__init__(64, 'Capability: Graceful Restart')
        if time.bit_length() > 12:
            raise ValueError('Time must be a 12-bit integer.')
        self.restart_state = int(restart_state)
        self.graceful_notification = int(graceful_notification)
        self.time = IntField((self.restart_state << 15) | (self.graceful_notification << 14) | time, 2, 'Flags/Time')
        self.append(self.time)
        self.length.dependencies.append(self.time)


class FourOctetASNumber(Capability):  # 65
    def __init__(self, asn: int) -> None:
        super().__init__(65, 'Capability: Four Octet AS Number')
        self.asn = IntField(asn, 4, 'AS Number')
        self.append(self.asn)
        self.length.dependencies.append(self.asn)


class Dynamic(Capability):  # 67
    def __init__(self):
        super().__init__(67, 'Capability: Dynamic')


class AdditionalPaths(Capability):  # 69
    def __init__(self, afi: int, safi: int, receive: bool) -> None:
        super().__init__(69, 'Capability: Additional Paths')
        self.afi = IntField(afi, 2, 'AFI')
        self.safi = IntField(safi, 1, 'SAFI')
        self.receive = IntField(int(receive), 1, 'Send/Receive')
        fields = [self.afi, self.safi, self.receive]
        self.extend(fields)
        self.length.dependencies.extend(fields)


class EnhancedRouteRefresh(Capability):  # 70
    def __init__(self) -> None:
        super().__init__(70, 'Capability: Enhanced Route Refresh')


class LongLivedGracefulRestart(Capability):  # 71
    def __init__(self, unknown: int) -> None:
        super().__init__(71, 'Capability: Long Lived Graceful Restart')
        self.unknown = IntField(unknown, 7, 'Unknown')
        self.append(self.unknown)
        self.length.dependencies.append(self.unknown)


class FQDN(Capability):  # 73
    def __init__(self, hostname: str, domain_name: str):
        super().__init__(73, 'Capability: FQDN')
        self.hostname = StringField(hostname, 'Hostname')
        self.hostname_length = LengthField([self.hostname], 1, 'Hostname Length')
        self.domain_name = StringField(domain_name, 'Domain Name')
        self.domain_name_length = LengthField([self.domain_name], 1, 'Domain Name Length')
        fields = [self.hostname_length, self.hostname, self.domain_name_length, self.domain_name]
        self.extend(fields)
        self.length.dependencies.extend(fields)


class SoftwareVersion(Capability):  # 75
    # FRRouting/10.1.1
    def __init__(self, software_version: str) -> None:
        super().__init__(75, 'Capability: Software Version')
        self.software_version = StringField(software_version, 'Software Version')
        self.software_version_length = LengthField([self.software_version], 1, 'Software Version Length')
        self.append(self.software_version_length)
        self.append(self.software_version)


class PathsLimit(Capability):  # 76
    """
    Unknown, dont use this?
    Example has value 0x0001010000
    """

    def __init__(self, unknown: int) -> None:
        super().__init__(76, 'Capability: Paths Limit')
        self.unknown = IntField(unknown, 5, 'Unknown')
        self.append(self.unknown)
        self.length.dependencies.append(self.unknown)


class OptionalParameter(ListField):
    """
    Optional Parameter Types:
        - Authentication (1)
        - Capability (2)
    """

    def __init__(self, type_code: int) -> None:
        self.param_type = IntField(type_code, 1, 'Parameter Type')
        self.param_length = LengthField([], 1, 'Parameter Length')
        self.capability = None
        super().__init__([self.param_type, self.param_length], 'Optional Parameter: Capability' if type_code == 2 else 'Optional Parameter: Authentication')

    def set_capability(self, capability: Capability) -> None:
        if self.capability is not None:
            raise ValueError('Capability already set.')
        self.capability = capability
        self.append(self.capability)
        self.param_length.dependencies.append(self.capability)

    def to_bytes(self) -> bytes:
        if self.capability is None:
            raise ValueError('Capability not set.')
        return super().to_bytes()


class BGPHeader(ListField):
    def __init__(self, type: int, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.marker = IntField(marker, 16, 'Marker')
        self.type = IntField(type, 1, 'Type')
        self.length = LengthField(None, 2, 'Length')
        self.length.dependencies = [self.marker, self.length, self.type]
        super().__init__([self.marker, self.length, self.type], 'BGP Header')
