from fields import ListField, IntField, LengthField
from bgp_fields import IPv4AddressField, BGPHeader, NetworkLayerReachabilityInformation


class BGPOpen(ListField):
    def __init__(self, bgp_version: int, my_ipv4: str, my_asn: int, hold_time: int, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.header = BGPHeader(1, marker)
        self.version = IntField(bgp_version, 1, 'Version')
        self.my_as = IntField(my_asn, 2, 'My AS')
        self.hold_time = IntField(hold_time, 2, 'Hold Time')
        self.bgp_id = IPv4AddressField(my_ipv4, 4, 'BGP Identifier')
        self.optional_parameters = ListField([], 'Optional Parameters')
        self.opt_params_length = LengthField([self.optional_parameters], 1, 'Optional Parameters Length')
        fields = [self.header, self.version, self.my_as, self.hold_time, self.bgp_id, self.opt_params_length, self.optional_parameters]
        super().__init__(fields, 'BGP Open')
        self.header.length.dependencies.extend(fields[1:])


class BGPUpdate(ListField):
    def __init__(self, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):
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
        return super().to_bytes()


class BGPNotification(ListField):
    def __init__(self, major_error: int, minor_error: int, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.header = BGPHeader(3, marker)
        self.major_error = IntField(major_error, 1, 'Major Error Code')
        self.minor_error = IntField(minor_error, 1, 'Minor Error Code')
        fields = [self.header, self.major_error, self.minor_error]
        super().__init__(fields, 'BGP Notification')
        self.header.length.dependencies.extend(fields[1:])


class BGPKeepAlive(ListField):
    def __init__(self, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.header = BGPHeader(4, marker)
        super().__init__([self.header], 'BGP KeepAlive')
