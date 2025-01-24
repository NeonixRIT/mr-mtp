"""
Examples of creating valid BGP messages of all types

Verify the functionality of the parse function for each BGP message type.
"""

from fields import IntField, StringField, ListField, LengthField, Field, MetaField
from bgp_fields import (
    IPv4AddressField,
    PathAttribute,
    Origin,
    ASPath,
    NextHop,
    MultiExitDisc,
    LocalPref,
    NetworkLayerReachabilityInformation,
    Capability,
    MultiprotocolExtensions,
    RouteRefresh,
    BGPExtended,
    GracefulRestart,
    FourOctetASNumber,
    Dynamic,
    AdditionalPaths,
    EnhancedRouteRefresh,
    LongLivedGracefulRestart,
    FQDN,
    SoftwareVersion,
    PathsLimit,
    OptionalParameter,
    BGPHeader,
)
from bgp_messages import BGPUpdate, BGPNotification, BGPKeepAlive, BGPOpen, parse_bytes


def test_open_parsing():
    # Create a BGP OPEN message
    open_original = BGPOpen(4, '192.168.0.1', 64510, 15)
    # Define Capabilities for the OPEN message
    capabilities = [
        MultiprotocolExtensions(1, 1),
        RouteRefresh(),
        EnhancedRouteRefresh(),
        FourOctetASNumber(64510),
        BGPExtended(),
        AdditionalPaths(1, 1, True),
        PathsLimit(0x0001010000),
        GracefulRestart(False, True, 120),
        LongLivedGracefulRestart(0x00010180000000),
    ]
    # Define Optional Parameter wrappers for each of the Capabilities (I.E. type 2 Optional Parameters)
    opt_params = [OptionalParameter(2) for _ in range(len(capabilities))]

    # Set the Capability for each Optional Parameter
    for i, capability in enumerate(capabilities):
        opt_params[i].set_capability(capability)

    # Add the Optional Parameters to the OPEN message
    open_original.optional_parameters.extend(opt_params)

    # Convert the OPEN message to bytes
    open_original_bytes = open_original.to_bytes()

    # Parse bytes into a BGP OPEN message
    open_parsed = BGPOpen.parse(open_original_bytes)

    # Convert the parsed OPEN message to bytes
    open_parsed_bytes = open_parsed.to_bytes()

    # Assert that the original and parsed OPEN messages are the same
    assert open_original_bytes == open_parsed_bytes


def test_open_parsing_2():
    open_original_bytes = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x7d\x01\x04\xfc\x00\x00\x0f\xc0\xa8\x00\xfe\x60\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x02\x00\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\xfc\x00\x02\x02\x06\x00\x02\x06\x45\x04\x00\x01\x01\x01\x02\x07\x4c\x05\x00\x01\x01\x00\x00\x02\x02\x43\x00\x02\x07\x49\x05\x03T-1\x00\x02\x04@\x02@x\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00\x02\x13\x4b\x11\x10\x46\x52\x52\x6f\x75\x74\x69\x6e\x67\x2f\x31\x30\x2e\x32\x2e\x31'
    open_parsed = BGPOpen.parse(open_original_bytes)
    open_parsed_bytes = open_parsed.to_bytes()
    assert open_original_bytes == open_parsed_bytes


def test_update_parsing_2asn():
    # Create a BGP UPDATE message with 2-byte ASNs
    update_original = BGPUpdate()

    # Define the Path Attributes for the UPDATE message
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 2, [64510, 64511, 64512, 64513])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    local_pref = LocalPref(0x40, 100)

    # Define the Network Layer Reachability Information for the UPDATE message
    nlri = NetworkLayerReachabilityInformation('192.168.1.0', 24)

    # Add the Path Attributes to the UPDATE message
    update_original.path_attributes.extend([origin, as_path, next_hop, med, local_pref])

    # Set the Network Layer Reachability Information for the UPDATE message
    update_original.set_nlri(nlri)

    # Convert the UPDATE message to bytes
    update_original_bytes = update_original.to_bytes()

    # Parse bytes into a BGP UPDATE message
    update_parsed = BGPUpdate.parse(update_original_bytes)

    # Convert the parsed UPDATE message to bytes
    update_parsed_bytes = update_parsed.to_bytes()

    # Assert that the original and parsed UPDATE messages are the same
    assert update_original_bytes == update_parsed_bytes


def test_update_parsing_4asn():
    # Create a BGP UPDATE message with 4-byte ASNs
    update_original = BGPUpdate()

    # Define the Path Attributes for the UPDATE message
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 4, [64510, 64511, 64512, 64513])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    local_pref = LocalPref(0x40, 100)

    # Define the Network Layer Reachability Information for the UPDATE message
    nlri = NetworkLayerReachabilityInformation('192.168.1.0', 24)

    # Add the Path Attributes to the UPDATE message
    update_original.path_attributes.extend([origin, as_path, next_hop, med, local_pref])

    # Set the Network Layer Reachability Information for the UPDATE message
    update_original.set_nlri(nlri)

    # Convert the UPDATE message to bytes
    update_original_bytes = update_original.to_bytes()

    # Parse bytes into a BGP UPDATE message
    update_parsed = BGPUpdate.parse(update_original_bytes)

    # Convert the parsed UPDATE message to bytes
    update_parsed_bytes = update_parsed.to_bytes()

    # Assert that the original and parsed UPDATE messages are the same
    assert update_original_bytes == update_parsed_bytes


def test_multiple_update_parsing():
    # Create a BGP UPDATE messages with 4-byte ASNs
    update_original_1 = BGPUpdate()
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 4, [64510, 64511, 64512, 64513])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    local_pref = LocalPref(0x40, 100)
    nlri = NetworkLayerReachabilityInformation('192.168.1.0', 24)
    update_original_1.path_attributes.extend([origin, as_path, next_hop, med, local_pref])
    update_original_1.set_nlri(nlri)
    update_original_1_bytes = update_original_1.to_bytes()
    update_parsed_1 = BGPUpdate.parse(update_original_1_bytes)
    update_parsed_1_bytes = update_parsed_1.to_bytes()
    assert update_original_1_bytes == update_parsed_1_bytes

    update_original_2 = BGPUpdate()
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 4, [64510, 64511, 64513])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    local_pref = LocalPref(0x40, 100)
    nlri = NetworkLayerReachabilityInformation('192.168.2.0', 24)
    update_original_2.path_attributes.extend([origin, as_path, next_hop, med, local_pref])
    update_original_2.set_nlri(nlri)
    update_original_2_bytes = update_original_2.to_bytes()
    update_parsed_2 = BGPUpdate.parse(update_original_2_bytes)
    update_parsed_2_bytes = update_parsed_2.to_bytes()
    assert update_original_2_bytes == update_parsed_2_bytes

    update_original_3 = BGPUpdate()
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 4, [64510, 64513])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    local_pref = LocalPref(0x40, 100)
    nlri = NetworkLayerReachabilityInformation('192.168.2.0', 24)
    update_original_3.path_attributes.extend([origin, as_path, next_hop, med, local_pref])
    update_original_3.set_nlri(nlri)
    update_original_3_bytes = update_original_3.to_bytes()
    update_parsed_3 = BGPUpdate.parse(update_original_3_bytes)
    update_parsed_3_bytes = update_parsed_3.to_bytes()
    assert update_original_3_bytes == update_parsed_3_bytes

    update_original_4 = BGPUpdate()
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 4, [64510, 12345])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    nlri = NetworkLayerReachabilityInformation('192.168.3.0', 24)
    update_original_4.path_attributes.extend([origin, as_path, next_hop, med])
    update_original_4.set_nlri(nlri)
    update_original_4_bytes = update_original_4.to_bytes()
    update_parsed_4 = BGPUpdate.parse(update_original_4_bytes)
    update_parsed_4_bytes = update_parsed_4.to_bytes()
    assert update_original_4_bytes == update_parsed_4_bytes

    update_original_5 = BGPUpdate()
    update_original_5_bytes = update_original_5.to_bytes()
    update_parsed_5 = BGPUpdate.parse(update_original_5_bytes)
    update_parsed_5_bytes = update_parsed_5.to_bytes()
    assert update_original_5_bytes == update_parsed_5_bytes

    original_messages = [update_original_1, update_original_2, update_original_3, update_original_4, update_original_5]
    original_combined_data = b''
    for message in original_messages:
        original_combined_data += message.to_bytes()
    parsed_messages = parse_bytes(original_combined_data)

    for i, actual_message in enumerate(parsed_messages):
        expected_message = original_messages[i]
        assert actual_message.to_bytes() == expected_message.to_bytes(), f'Message {i} did not match. Expected: {expected_message.to_bytes()}, Actual: {actual_message.to_bytes()}'


def test_notification_parsing():
    # Create a BGP NOTIFICATION message
    notification_original = BGPNotification(1, 2)

    # Convert the NOTIFICATION message to bytes
    notification_original_bytes = notification_original.to_bytes()

    # Parse bytes into a BGP NOTIFICATION message
    notification_parsed = BGPNotification.parse(notification_original_bytes)

    # Convert the parsed NOTIFICATION message to bytes
    notification_parsed_bytes = notification_parsed.to_bytes()

    # Assert that the original and parsed NOTIFICATION messages are the same
    assert notification_original_bytes == notification_parsed_bytes


def test_keepalive_parsing():
    # Create a BGP KEEPALIVE message
    keepalive_original = BGPKeepAlive()

    # Convert the KEEPALIVE message to bytes
    keepalive_original_bytes = keepalive_original.to_bytes()

    # Parse bytes into a BGP KEEPALIVE message
    keepalive_parsed = BGPKeepAlive.parse(keepalive_original_bytes)

    # Convert the parsed KEEPALIVE message to bytes
    keepalive_parsed_bytes = keepalive_parsed.to_bytes()

    # Assert that the original and parsed KEEPALIVE messages are the same
    assert keepalive_original_bytes == keepalive_parsed_bytes


if __name__ == '__main__':
    test_open_parsing()
    test_open_parsing_2()
    test_update_parsing_2asn()
    test_update_parsing_4asn()
    test_notification_parsing()
    test_keepalive_parsing()
    test_multiple_update_parsing()
