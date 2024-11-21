BGP_VERSION = 4
ASN_SIZE = 4


class Field:
    def __init__(self, value, size: int, name: str) -> None:
        self.value = value
        self.size = size
        self.name = name

    def to_bytes(self) -> bytes:
        raise NotImplementedError('Method `to_bytes` must be implemented in subclasses.')

    def __len__(self):
        return self.size


class MetaField(Field):
    def __init__(self, dependencies: list[Field], size: int, name: str) -> None:
        super().__init__(None, size, name)
        self.dependencies = dependencies

    def derive(self):
        raise NotImplementedError('Method `derive` must be implemented in subclasses.')


class IntField(Field):
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(self.size, 'big')


class StringField(Field):
    def __init__(self, value: str, name: str) -> None:
        super().__init__(value, len(value), name)

    def to_bytes(self) -> bytes:
        return self.value.encode()


class ListField(Field):
    def __init__(self, value: list[Field | MetaField], name: str) -> None:
        size = 0
        for val in value:
            size += val.size
        super().__init__(value, size, name)


    def to_bytes(self) -> bytes:
        return b''.join([val.to_bytes() for val in self.value])

    def append(self, value: Field | MetaField ) -> None:
        self.value.append(value)
        self.size += value.size

    def extend(self, values: list[Field | MetaField]) -> None:
        self.value.extend(values)
        for val in values:
            self.size += val.size

    def __repr__(self):
        tab_spaces = 4
        result = self.name + '\n'
        titles_and_values: list[int, Field | MetaField, str, str] = []
        for field in self.value:
            if isinstance(field, ListField):
                lines = [val for val in repr(field).split('\n') if val]
                for line in lines:
                    depth = 1 + ((len(line) - len(line.lstrip())) // tab_spaces)
                    line = line.strip()
                    tokens = line.split(':')
                    title = ''
                    value = ''
                    if len(tokens) == 1:
                        title = tokens[0]
                    elif len(tokens) == 2:
                        try:
                            int(tokens[-1], 16)
                            title, value = tokens
                        except ValueError:
                            title = f'{tokens[0].strip()}: {tokens[1].strip()}'
                    prefix_str = ' ' * (tab_spaces * depth)
                    titles_and_values.append((prefix_str + title, value))
            else:
                depth = 1
                prefix_str = ' ' * (tab_spaces * depth)
                titles_and_values.append((prefix_str + field.name, field.to_bytes().hex().lower()))
        title_l_just = max([len(title) for title, _ in titles_and_values]) + 1
        value_r_just = max([len(value) for _, value in titles_and_values]) + 1

        for title, value in titles_and_values:
            if not value:
                result += f'{title}\n'
            else:
                result += f'{title.ljust(title_l_just)}:{value.rjust(value_r_just)}\n'
        return result


class IPv4AddressField(Field):
    def __init__(self, value: str, size: int, name: str) -> None:
        super().__init__(value, size, name)

    def to_bytes(self) -> bytes:
        octets = self.value.split('.')
        if len(octets) != 4:
            raise ValueError('Invalid IP address.')
        return b''.join([int(octet).to_bytes(1, 'big') for octet in octets[:self.size]])


class LengthField(MetaField):
    def derive(self) -> int:
        if self.dependencies is None:
            raise ValueError('LengthField must have dependencies.')
        length = 0
        for field in self.dependencies:
            length += len(field)
        return length

    def to_bytes(self) -> bytes:
        if self.dependencies is None:
            raise ValueError('LengthField must have dependencies.')
        return self.derive().to_bytes(self.size, 'big')


class PathAttribute(ListField):
    def __init__(self, flags: int, type_code: int, name: str) -> None:
        '''
        0... ....: Optional
        .0.. ....: Transitive
        ..0. ....: Partial
        ...0 ....: Extended Length
        .... 0000: Unused
        '''
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
    '''
    Origin Codes:
        - IGP (0)
        - EGP (1)
        - INCOMPLETE (2)
    '''
    def __init__(self, flags, origin) -> None:
        super().__init__(flags, 1, 'Path Attribute: Origin')
        self.origin = IntField(origin, 1, 'Origin')
        self.append(self.origin)
        self.length.dependencies = [self.origin]


class ASPath(PathAttribute):
    def __init__(self, flags: int, asns: list[int]) -> None:
        super().__init__(flags, 2, 'Path Attribute: AS Path')
        self.segment_type = IntField(2, 1, 'Segment Type')
        self.segment_length = IntField(len(asns), 1, 'Segment Length')
        asns = [IntField(asn, ASN_SIZE, f'ASN {i}') for i, asn in enumerate(asns)]
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


class MultiprotocolExtensions(Capability): # 1
    '''
    AFI:
        - IPv4 (1)
        - IPv6 (2)
        - L2VPN (25)
    SAFI:
        - Unicast (1)
        - Multicast (2)
        - MPLS (4)
        - EVPN (70)
    '''
    def __init__(self, afi: int, safi: int) -> None:
        super().__init__(1, 'Capability: Multiprotocol Extensions')
        self.afi = IntField(afi, 2, 'AFI')
        self.reserved = IntField(0, 1, 'Reserved')
        self.safi = IntField(safi, 1, 'SAFI')
        self.append(self.afi)
        self.append(self.reserved)
        self.append(self.safi)
        self.length.dependencies.extend([self.afi, self.reserved, self.safi])


class RouteRefresh(Capability): # 2
    def __init__(self) -> None:
        super().__init__(2, 'Capability: Route Refresh')


class BGPExtended(Capability): # 6
    def __init__(self):
        super().__init__(6, 'Capability: BGP Extended')


class GracefulRestart(Capability): # 64
    '''
    0... .... .... .... = Restart State
    .0.. .... .... .... = Graceful Notification
    .... 0000 0000 0000 = Time
    '''
    def __init__(self, restart_state: bool, graceful_notification: bool, time: int) -> None:
        super().__init__(64, 'Capability: Graceful Restart')
        if time.bit_length() > 12:
            raise ValueError('Time must be a 12-bit integer.')
        self.restart_state = int(restart_state)
        self.graceful_notification = int(graceful_notification)
        self.time = IntField((self.restart_state << 15) | (self.graceful_notification << 14) | time, 2, 'Flags/Time')
        self.append(self.time)
        self.length.dependencies.append(self.time)


class FourOctetASNumber(Capability): # 65
    def __init__(self, asn: int) -> None:
        super().__init__(65, 'Capability: Four Octet AS Number')
        self.asn = IntField(asn, 4, 'AS Number')
        self.append(self.asn)
        self.length.dependencies.append(self.asn)


class Dynamic(Capability): # 67
    def __init__(self):
        super().__init__(67, 'Capability: Dynamic')


class AdditionalPaths(Capability): # 69
    def __init__(self, afi: int, safi: int, receive: bool) -> None:
        super().__init__(69, 'Capability: Additional Paths')
        self.afi = IntField(afi, 2, 'AFI')
        self.safi = IntField(safi, 1, 'SAFI')
        self.receive = IntField(int(receive), 1, 'Send/Receive')
        fields = [self.afi, self.safi, self.receive]
        self.extend(fields)
        self.length.dependencies.extend(fields)


class EnhancedRouteRefresh(Capability): # 70
    def __init__(self) -> None:
        super().__init__(70, 'Capability: Enhanced Route Refresh')


class LongLivedGracefulRestart(Capability): # 71
    def __init__(self, unknown: int) -> None:
        super().__init__(71, 'Capability: Long Lived Graceful Restart')
        self.unknown = IntField(unknown, 7, 'Unknown')
        self.append(self.unknown)
        self.length.dependencies.append(self.unknown)


class FQDN(Capability): # 73
    def __init__(self, hostname: str, domain_name: str):
        super().__init__(73, 'Capability: FQDN')
        self.hostname = StringField(hostname, 'Hostname')
        self.hostname_length = LengthField([self.hostname], 1, 'Hostname Length')
        self.domain_name = StringField(domain_name, 'Domain Name')
        self.domain_name_length = LengthField([self.domain_name], 1, 'Domain Name Length')
        fields = [self.hostname_length, self.hostname, self.domain_name_length, self.domain_name]
        self.extend(fields)
        self.length.dependencies.extend(fields)


class SoftwareVersion(Capability): # 75
    # FRRouting/10.1.1
    def __init__(self, software_version: str) -> None:
        super().__init__(75, 'Capability: Software Version')
        self.software_version = StringField(software_version, 'Software Version')
        self.software_version_length = LengthField([self.software_version], 1, 'Software Version Length')
        self.append(self.software_version_length)
        self.append(self.software_version)


class PathsLimit(Capability): # 76
    '''
    Unknown, dont use this?
    Example has value 0x0001010000
    '''
    def __init__(self, unknown: int) -> None:
        super().__init__(76, 'Capability: Paths Limit')
        self.unknown = IntField(unknown, 5, 'Unknown')
        self.append(self.unknown)
        self.length.dependencies.append(self.unknown)


class OptionalParameter(ListField):
    '''
    Optional Parameter Types:
        - Authentication (1)
        - Capability (2)
    '''
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
    def __init__(self, type: int, marker=0xffffffffffffffffffffffffffffffff) -> None:
        self.marker = IntField(marker, 16, 'Marker')
        self.type = IntField(type, 1, 'Type')
        self.length = LengthField(None, 2, 'Length')
        self.length.dependencies = [self.marker, self.length, self.type]
        super().__init__([self.marker, self.length, self.type], 'BGP Header')


class BGPOpen(ListField):
    def __init__(self, my_ipv4: str, my_asn: int, hold_time: int, marker=0xffffffffffffffffffffffffffffffff) -> None:
        self.header = BGPHeader(1, marker)
        self.version = IntField(BGP_VERSION, 1, 'Version')
        self.my_as = IntField(my_asn, 2, 'My AS')
        self.hold_time = IntField(hold_time, 2, 'Hold Time')
        self.bgp_id = IPv4AddressField(my_ipv4, 4, 'BGP Identifier')
        self.optional_parameters = ListField([], 'Optional Parameters')
        self.opt_params_length = LengthField([self.optional_parameters], 1, 'Optional Parameters Length')
        fields = [self.header, self.version, self.my_as, self.hold_time, self.bgp_id, self.opt_params_length, self.optional_parameters]
        super().__init__(fields, 'BGP Open')
        self.header.length.dependencies.extend(fields[1:])


class BGPUpdate(ListField):
    def __init__(self, marker=0xffffffffffffffffffffffffffffffff):
        self.header = BGPHeader(2, marker)
        self.withdrawn_routes_length = LengthField([], 2, 'Withdrawn Routes Length')
        self.total_path_attribute_length = LengthField(None, 2, 'Total Path Attribute Length')
        self.path_attributes = ListField([], 'Path Attributes')
        self.nlri = None

        fields = [
            self.header,
            self.withdrawn_routes_length,
            self.total_path_attribute_length,
            self.path_attributes,
        ]
        self.total_path_attribute_length.dependencies = [self.path_attributes]
        super().__init__(fields, 'BGP Update')
        self.header.length.dependencies.extend([self.withdrawn_routes_length, self.total_path_attribute_length, self.path_attributes])

    def set_nlri(self, nlri: NetworkLayerReachabilityInformation) -> None:
        if self.nlri is not None:
            raise ValueError('NLRI already set.')
        self.nlri = nlri
        self.append(nlri)
        self.header.length.dependencies.append(nlri)

    def to_bytes(self) -> bytes:
        if self.nlri is None:
            raise ValueError('NLRI not set.')
        return super().to_bytes()


class BGPNotification(ListField):
    def __init__(self, major_error: int, minor_error: int, marker=0xffffffffffffffffffffffffffffffff) -> None:
        self.header = BGPHeader(3, marker)
        self.major_error = IntField(major_error, 1, 'Major Error Code')
        self.minor_error = IntField(minor_error, 1, 'Minor Error Code')
        fields = [self.header, self.major_error, self.minor_error]
        super().__init__(fields, 'BGP Notification')
        self.header.length.dependencies.extend(fields[1:])


class BGPKeepAlive(ListField):
    def __init__(self, marker=0xffffffffffffffffffffffffffffffff) -> None:
        self.header = BGPHeader(4, marker)
        super().__init__([self.header], 'BGP KeepAlive')


def print_open():
    data = BGPOpen('192.168.0.254', 64512, 15)
    capabilities = [
        MultiprotocolExtensions(1, 1),
        RouteRefresh(),
        EnhancedRouteRefresh(),
        FourOctetASNumber(64512),
        BGPExtended(),
        AdditionalPaths(1, 1, True),
        PathsLimit(0x0001010000),
        Dynamic(),
        FQDN('T-1', ''),
        GracefulRestart(False, True, 120),
        LongLivedGracefulRestart(0x00010180000000),
        SoftwareVersion('FRRouting/10.1.1')
    ]
    opt_params = [OptionalParameter(2) for _ in range(len(capabilities))]
    for i, capability in enumerate(capabilities):
        opt_params[i].set_capability(capability)

    data.optional_parameters.extend(opt_params)
    print(data, '\n', f'OPEN: {data.to_bytes().hex().lower()}', sep='')
    print('-' * 95)


def print_update():
    update = BGPUpdate()
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, [64510])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    nlri = NetworkLayerReachabilityInformation('192.168.1.0', 24)
    update.path_attributes.extend([origin, as_path, next_hop, med])
    update.set_nlri(nlri)
    print(update, '\n', f'UPDATE: {update.to_bytes().hex().lower()}', sep='')
    print('-' * 80)


def test_notification():
    data = BGPNotification(1, 1)
    print(data, '\n', f'NOTIFICATION: {data.to_bytes().hex().lower()}', sep='')
    print('-' * 80)


def test_keepalive():
    data = BGPKeepAlive()
    print(data, '\n', f'KEEPALIVE: {data.to_bytes().hex().lower()}', sep='')
    print('-' * 80)


def main():
    print_open()
    print_update()
    test_notification()
    test_keepalive()


if __name__ == '__main__':
    main()
