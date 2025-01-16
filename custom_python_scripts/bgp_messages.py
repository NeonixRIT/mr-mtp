"""
This file contains definitions for the four BGP message types, outlining their structure and how to convert them to/from bytes.
"""

from fields import ListField, IntField, LengthField
from bgp_fields import IPv4AddressField, BGPHeader, NetworkLayerReachabilityInformation, OptionalParameter, Origin, ASPath, NextHop, MultiExitDisc, LocalPref

PA_TYPE_MAP = {
    1: Origin,
    2: ASPath,
    3: NextHop,
    4: MultiExitDisc,
    5: LocalPref,
}


class BGPOpen(ListField):
    """
    BGP Open message.

    Is a BGP Header with type 1 and the following additional information:
        - Version (int)
        - My AS (int)
        - Hold Time (int)
        - BGP Identifier (IPv4 Address)
        - Optional Parameters Length (int)
        - Optional Parameters (List of OptionalParameters)

    Used when starting a BGP session with a peer to negotiate session parameters.
    """

    def __init__(self, bgp_version: int, my_ipv4: str, my_asn: int, hold_time: int, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        """
        Initialize a BGP Open message.

        args:
            bgp_version: The BGP version to use.
            my_ipv4: The IPv4 address of the sender.
            my_asn: The ASN of the sender.
            hold_time: The hold time for the session.
            marker: The marker for the BGP Header.
        """
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

    def parse(data: bytes) -> 'BGPOpen':
        marker = int.from_bytes(data[:16], 'big')
        expected_length = int.from_bytes(data[16:18], 'big')
        bgp_version = int.from_bytes(data[19:20], 'big')
        my_asn = int.from_bytes(data[20:22], 'big')
        hold_time = int.from_bytes(data[22:24], 'big')
        my_ipv4 = '.'.join([str(int(byte)) for byte in data[24:28]])

        temp_open = BGPOpen(bgp_version, my_ipv4, my_asn, hold_time, marker)
        opt_params_data = data[29:]
        opt_params = []
        while opt_params_data:
            param_length = opt_params_data[1] + 2
            opt_params.append(OptionalParameter.parse(opt_params_data[:param_length]))
            opt_params_data = opt_params_data[param_length:]
        temp_open.optional_parameters.extend(opt_params)
        actual_length = temp_open.header.length.derive()
        if expected_length != actual_length:
            raise ValueError(f'Error occurred while parsing BGPOpen, causing header Length to not be the expected value: `{expected_length}` != `{actual_length}`.')
        return temp_open


class BGPUpdate(ListField):
    """
    BGP Update message.

    Is a BGP header with type 2 and the following additional information:
        - Withdrawn Routes Length (int)
        - Total Path Attribute Length (int)
        - Path Attributes (List of PathAttributes)
        - Network Layer Reachability Information (NLRI)

    Used to advertise new routes, withdraw old routes, and update route attributes.

    Path Attribute and NLRI information must be set after creation.

    TODO: Implement Withdrawn Routes. List of NLRI to withdraw.
    """

    def __init__(self, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):
        self.header = BGPHeader(2, marker)
        self.withdrawn_routes_length = LengthField([], 2, 'Withdrawn Routes Length')
        # self.withdrawn_routes = ListField([], 'Withdrawn Routes')
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

    def parse(data: bytes) -> 'BGPUpdate':
        marker = int.from_bytes(data[:16], 'big')
        expected_length = int.from_bytes(data[16:18], 'big')
        temp_update = BGPUpdate(marker)

        # TODO: Parse Withdrawn Routes?
        withdrawn_routes_length = int.from_bytes(data[19:21], 'big')
        if withdrawn_routes_length:
            raise NotImplementedError('Parsing of Withdrawn Routes not implemented.')

        # Parse Path Attributes
        total_path_attributes_length = int.from_bytes(data[21:23], 'big')
        path_attributes_data = data[23 : 23 + total_path_attributes_length]
        pa_type_map = PA_TYPE_MAP
        path_attributes = []
        while path_attributes_data:
            flags = path_attributes_data[0]
            type_code = path_attributes_data[1]
            length_size = 2 if flags & 0b00010000 == 0b00010000 else 1
            length = int.from_bytes(path_attributes_data[2 : 2 + length_size], 'big') + 2 + length_size
            pa_data = path_attributes_data[:length]
            path_attrib = pa_type_map[type_code].parse(pa_data)
            path_attributes.append(path_attrib)
            path_attributes_data = path_attributes_data[length:]
        temp_update.path_attributes.extend(path_attributes)

        # Parse NLRI
        nlri_data = data[23 + total_path_attributes_length:27 + total_path_attributes_length]
        if nlri_data:
            nlri = NetworkLayerReachabilityInformation.parse(nlri_data)
            temp_update.set_nlri(nlri)

        # Check if the expected length matches the actual length
        actual_length = temp_update.header.length.derive()
        if expected_length != actual_length:
            raise ValueError(f'Error occurred while parsing BGPUpdate, causing header length to not be the expected value: `{expected_length}` != `{actual_length}`.')
        return temp_update


class BGPNotification(ListField):
    """
    BGP Notification message.

    Used to indicate an error in the BGP session.

    Is a BGP Header with type 3 and the following additional information:
        - Major Error Code (int)
        - Minor Error Code (int)
    """

    def __init__(self, major_error: int, minor_error: int, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.header = BGPHeader(3, marker)
        self.major_error = IntField(major_error, 1, 'Major Error Code')
        self.minor_error = IntField(minor_error, 1, 'Minor Error Code')
        fields = [self.header, self.major_error, self.minor_error]
        super().__init__(fields, 'BGP Notification')
        self.header.length.dependencies.extend(fields[1:])

    def parse(data: bytes) -> 'BGPNotification':
        marker = int.from_bytes(data[:16], 'big')
        major_error = int.from_bytes(data[19:20], 'big')
        minor_error = int.from_bytes(data[20:21], 'big')
        return BGPNotification(major_error, minor_error, marker)


class BGPKeepAlive(ListField):
    """
    BGP KeepAlive message.

    Is a BGP Header with type 4 and no additional data.
    """

    def __init__(self, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.header = BGPHeader(4, marker)
        super().__init__([self.header], 'BGP KeepAlive')

    def parse(data: bytes) -> 'BGPKeepAlive':
        marker = int.from_bytes(data[:16], 'big')
        return BGPKeepAlive(marker)


MESSAGE_TYPE_MAP: dict[int, ListField] = {
    1: BGPOpen,
    2: BGPUpdate,
    3: BGPNotification,
    4: BGPKeepAlive,
}

def get_message_type_num(data: bytes) -> int:
    if len(data) < 19:
        raise ValueError(f'Invalid BGP packet length of `{len(data)}`. Expected at least 19 bytes.\nRaw Bytes: {data.hex()}')
    return int.from_bytes(data[18:19], 'big')

def parse_bytes(data: bytes) -> list[BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification]:
    """
    Parse BGP messages from bytes.

    args:
        data: The bytes to parse into a BGP message.

    returns:
        List of parsed BGP messages.
    """
    messages = []

    msg_type_map = MESSAGE_TYPE_MAP
    msg_type = get_message_type_num(data)
    if msg_type not in msg_type_map:
        raise ValueError(f'Unknown BGP packet type `{msg_type}`. Expected 1, 2, 3, or 4.\nRaw Bytes: {data.hex()}')

    parsed_message: BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification = msg_type_map[msg_type].parse(data)
    messages.append(parsed_message)

    data = data[parsed_message.header.length.derive():]
    while data:
        msg_type = get_message_type_num(data)
        if msg_type not in msg_type_map:
            raise ValueError(f'Unknown BGP packet type `{msg_type}`. Expected 1, 2, 3, or 4.\nRaw Bytes: {data.hex()}')
        parsed_message = msg_type_map[msg_type].parse(data)
        messages.append(parsed_message)
        data = data[parsed_message.header.length.derive():]
    return messages
