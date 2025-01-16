"""
This file contains definitions for fields found in BGP messages, outlining their structure and how to convert them to/from bytes.
"""

from fields import Field, MetaField, IntField, StringField, ListField, LengthField


class IPv4AddressField(Field):
    """
    Field to represent an IPv4 address.
    """

    def __init__(self, value: str, size: int, name: str) -> None:
        super().__init__(value, size, name)

    def to_bytes(self) -> bytes:
        octets = self.value.split('.')
        if len(octets) != 4:
            raise ValueError('Invalid IP address.')
        return b''.join([int(octet).to_bytes(1, 'big') for octet in octets[: self.size]])

    def parse(data, size, name) -> 'IPv4AddressField':
        octets = [str(int.from_bytes(data[i : i + 1], 'big')) for i in range(size)]
        return IPv4AddressField('.'.join(octets), size, name)


class PathAttribute(ListField):
    """
    Abstract Path Attribute Field

    All Path Attributes have the following structure:
        - Flags (1 byte)
        - Type Code (1 byte)
        - Length (1 or 2 bytes)
            - Length of its value, not including itself, Flags, and Type Code.
        - Value (variable length/structure)

    Type Code Meanings:
        0... ....: Optional
        .0.. ....: Transitive
        ..0. ....: Partial
        ...0 ....: Extended Length
        .... 0000: Unused
    """

    def __init__(self, flags: int, type_code: int, name: str) -> None:
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
        """
        Calculate the length of the whole field in bytes.
        Necessary for calculating the length value in the BGP Header properly.
        """
        return self.length.derive() + self.flags.size + self.type_code.size + self.length.size


class Origin(PathAttribute):
    """
    Origin Codes:
        - IGP (0)
        - EGP (1)
        - INCOMPLETE (2)
    """

    def __init__(self, flags, origin) -> None:
        # TODO: Verify origin value
        super().__init__(flags, 1, 'Path Attribute: Origin')
        self.origin = IntField(origin, 1, 'Origin')
        self.append(self.origin)
        self.length.dependencies = [self.origin]

    def parse(data: bytes) -> 'Origin':
        flags = data[0]
        origin = data[3]
        return Origin(flags, origin)


class ASPath(PathAttribute):
    """
    AS Path Field

    List of ASNs that the route has traversed, created using a list of integers.
    """

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

    def parse(data: bytes) -> 'ASPath':
        flags = data[0]
        num_asns = data[5]
        asn_size = (len(data) - 6) // num_asns
        asns = [int.from_bytes(data[i : i + asn_size], 'big') for i in range(6, len(data), asn_size)]
        return ASPath(flags, asn_size, asns)


class NextHop(PathAttribute):
    """
    Next Hop Field

    The IP address of the next hop router for this path.
    """

    def __init__(self, flags: int, next_hop: str) -> None:
        super().__init__(flags, 3, 'Path Attribute: Next Hop')
        self.next_hop = IPv4AddressField(next_hop, 4, 'Next Hop')
        self.append(self.next_hop)
        self.length.dependencies = [self.next_hop]

    def parse(data: bytes) -> 'NextHop':
        flags = data[0]
        next_hop = '.'.join([str(int(byte)) for byte in data[3:]])
        return NextHop(flags, next_hop)


class MultiExitDisc(PathAttribute):
    """
    Multi Exit Discriminator Field

    A metric used to determine the best path when multiple paths to the same destination exist.
    """

    def __init__(self, flags: int, med: int) -> None:
        super().__init__(flags, 4, 'Path Attribute: Multi Exit Disc')
        self.med = IntField(med, 4, 'MED')
        self.append(self.med)
        self.length.dependencies = [self.med]

    def parse(data: bytes) -> 'MultiExitDisc':
        flags = data[0]
        med = int.from_bytes(data[3:], 'big')
        return MultiExitDisc(flags, med)


class LocalPref(PathAttribute):
    """
    Local Preference Field

    The Local Preference attribute is used to identify the preferred route for an AS.
    """

    def __init__(self, flags: int, local_pref: int) -> None:
        super().__init__(flags, 5, 'Path Attribute: Local Preference')
        self.local_pref = IntField(local_pref, 4, 'Local Preference')
        self.append(self.local_pref)
        self.length.dependencies = [self.local_pref]

    def parse(data: bytes) -> 'LocalPref':
        flags = data[0]
        local_pref = int.from_bytes(data[3:], 'big')
        return LocalPref(flags, local_pref)


class NetworkLayerReachabilityInformation(ListField):
    """
    Network Layer Reachability Information Field

    Used in BGP Update messages.

    Defines the subnet that a route can be used to reach.
    """

    def __init__(self, address: str, prefix: int) -> None:
        self.prefix_length = IntField(prefix, 1, 'Prefix Length')
        self.address = IPv4AddressField(address, prefix // 8, 'Prefix')
        super().__init__([self.prefix_length, self.address], 'Network Layer Reachability Information')

    def __contains__(self, other: str | IPv4AddressField) -> bool:
        num_octets = self.prefix_length.value // 8
        if isinstance(other, IPv4AddressField):
            o_octets = list(other.to_bytes())
            s_octets = list(self.address.to_bytes())
            for i in range(num_octets):
                if o_octets[i] != s_octets[i]:
                    return False
            return True
        if isinstance(other, str):
            address = other
            if '/' in other:
                address, _ = other.split('/', 2)
            if len(address.split('.')) != 4:
                raise ValueError('Invalid address format. Expected IPv4 address.')
            return IPv4AddressField(address, 4, "") in self
        return False

    def __eq__(self, other) -> bool:
        if isinstance(other, NetworkLayerReachabilityInformation):
            return self.prefix_length == other.prefix_length and self.address == other.address
        if isinstance(other, str):
            if '/' not in other:
                raise ValueError('Invalid address format. Expected CIDR notation.')
            address, prefix_length = other.split('/', 2)
            if len(address.split('.')) != 4:
                raise ValueError('Invalid address format. Expected IPv4 address.')
            return self.prefix_length == int(prefix_length) and self.address.value == address
        return False

    def __hash__(self) -> int:
        return hash(f'{self.address.value}/{self.prefix_length.value}')


    def parse(data: bytes) -> 'NetworkLayerReachabilityInformation':
        prefix = int.from_bytes(data[:1], 'big')
        address = '.'.join([str(int(byte)) for byte in data[1:]]) + '.0'
        return NetworkLayerReachabilityInformation(address, prefix)


class Capability(ListField):
    """
    Abstract Capability Field

    Used in BGP Open messages to negotiate how two BGP peers should communicate.

    All Capabilities have the following structure:
        - Type Code (1 byte)
        - Length (1 byte)
        - Value (variable length/structure)

    """

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

    def parse(data: bytes) -> 'MultiprotocolExtensions':
        afi = int.from_bytes(data[2:4], 'big')
        safi = int.from_bytes(data[5:6], 'big')
        return MultiprotocolExtensions(afi, safi)


class RouteRefresh(Capability):  # 2
    def __init__(self) -> None:
        super().__init__(2, 'Capability: Route Refresh')

    def parse(data: bytes) -> 'RouteRefresh':
        return RouteRefresh()


class BGPExtended(Capability):  # 6
    def __init__(self):
        super().__init__(6, 'Capability: BGP Extended')

    def parse(data: bytes) -> 'BGPExtended':
        return BGPExtended()


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

    def parse(data: bytes) -> 'GracefulRestart':
        time = int.from_bytes(data, 'big')
        restart_state = bool(time & (1 << 15))
        graceful_notification = bool(time & (1 << 14))
        time = time & 0x3FFF
        return GracefulRestart(restart_state, graceful_notification, time)


class FourOctetASNumber(Capability):  # 65
    def __init__(self, asn: int) -> None:
        super().__init__(65, 'Capability: Four Octet AS Number')
        self.asn = IntField(asn, 4, 'AS Number')
        self.append(self.asn)
        self.length.dependencies.append(self.asn)

    def parse(data: bytes) -> 'FourOctetASNumber':
        return FourOctetASNumber(int.from_bytes(data[2:], 'big'))


class Dynamic(Capability):  # 67
    def __init__(self):
        super().__init__(67, 'Capability: Dynamic')

    def parse(data: bytes) -> 'Dynamic':
        return Dynamic()


class AdditionalPaths(Capability):  # 69
    def __init__(self, afi: int, safi: int, receive: bool) -> None:
        super().__init__(69, 'Capability: Additional Paths')
        self.afi = IntField(afi, 2, 'AFI')
        self.safi = IntField(safi, 1, 'SAFI')
        self.receive = IntField(int(receive), 1, 'Send/Receive')
        fields = [self.afi, self.safi, self.receive]
        self.extend(fields)
        self.length.dependencies.extend(fields)

    def parse(data: bytes) -> 'AdditionalPaths':
        afi = int.from_bytes(data[2:4], 'big')
        safi = int.from_bytes(data[4:5], 'big')
        receive = bool(data[5])
        return AdditionalPaths(afi, safi, receive)


class EnhancedRouteRefresh(Capability):  # 70
    def __init__(self) -> None:
        super().__init__(70, 'Capability: Enhanced Route Refresh')

    def parse(data: bytes) -> 'EnhancedRouteRefresh':
        return EnhancedRouteRefresh()


class LongLivedGracefulRestart(Capability):  # 71
    def __init__(self, unknown: int) -> None:
        super().__init__(71, 'Capability: Long Lived Graceful Restart')
        self.unknown = IntField(unknown, 7, 'Unknown')
        self.append(self.unknown)
        self.length.dependencies.append(self.unknown)

    def parse(data: bytes) -> 'LongLivedGracefulRestart':
        return LongLivedGracefulRestart(int.from_bytes(data[2:], 'big'))


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

    def parse(data: bytes) -> 'FQDN':
        hostname_length = int.from_bytes(data[:1], 'big')
        hostname = data[1 : 1 + hostname_length].decode()
        domain_name_length = int.from_bytes(data[1 + hostname_length : 2 + hostname_length], 'big')
        domain_name = data[2 + hostname_length : 2 + hostname_length + domain_name_length].decode()
        return FQDN(hostname, domain_name)


class SoftwareVersion(Capability):  # 75
    # FRRouting/10.1.1
    def __init__(self, software_version: str) -> None:
        super().__init__(75, 'Capability: Software Version')
        self.software_version = StringField(software_version, 'Software Version')
        self.software_version_length = LengthField([self.software_version], 1, 'Software Version Length')
        self.append(self.software_version_length)
        self.append(self.software_version)

    def parse(data: bytes) -> 'SoftwareVersion':
        return SoftwareVersion(data.decode())


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

    def parse(data: bytes) -> 'PathsLimit':
        return PathsLimit(int.from_bytes(data[2:], 'big'))


CAPABILITY_TYPE_MAP = {
    1: MultiprotocolExtensions,
    2: RouteRefresh,
    6: BGPExtended,
    64: GracefulRestart,
    65: FourOctetASNumber,
    67: Dynamic,
    69: AdditionalPaths,
    70: EnhancedRouteRefresh,
    71: LongLivedGracefulRestart,
    73: FQDN,
    75: SoftwareVersion,
    76: PathsLimit,
}


class OptionalParameter(ListField):
    """
    OptionalParameter Field.

    This field's Value is a Capability Field.

    All Optional Parameters have the following structure:
        - Parameter Type (1 byte)
        - Parameter Length (1 byte)
        - Value (variable length/structure)

    Parameter Type Values:
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

    def parse(data: bytes) -> 'OptionalParameter':
        capability_type_map = CAPABILITY_TYPE_MAP
        capability_type = data[2]
        if capability_type not in capability_type_map:
            raise ValueError(f'Unknown capability type: {capability_type}')
        capability = capability_type_map[capability_type].parse(data[2:])
        opt_param = OptionalParameter(2)
        opt_param.set_capability(capability)
        return opt_param


class BGPHeader(ListField):
    """
    BGP Header Field

    All BGP messages start with a BGP Header which has the following structure:
        - Marker (16 bytes)
        - Length (2 bytes)
            - Length of the entire message, including the header.
        - Type (1 byte)
    """

    def __init__(self, type: int, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.marker = IntField(marker, 16, 'Marker')
        self.type = IntField(type, 1, 'Type')
        self.length = LengthField(None, 2, 'Length')
        self.length.dependencies = [self.marker, self.length, self.type]
        super().__init__([self.marker, self.length, self.type], 'BGP Header')
